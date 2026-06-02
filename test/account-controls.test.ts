import { describe, expect, it, beforeEach } from 'vitest';
import { createTestHarness, type TestHarness } from './helpers.js';
import { generateToken, hashToken } from '../src/lib/tokens.js';

describe('account kill-switch controls (/account/disable, /account/enable)', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  /**
   * Creates a human + a live session and returns the cookie header.
   * `ageMs` backdates the session's auth event (created_at) to simulate
   * a stale — e.g. stolen long-lived — session for the §7.5 freshness
   * test. MemoryStore hands back the live object, so the mutation sticks.
   */
  async function signedIn(opts: { ageMs?: number } = {}) {
    const human = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
    const raw = generateToken();
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    const session = await h.store.createSession(human.id, hashToken(raw), expires);
    if (opts.ageMs) session.created_at = new Date(Date.now() - opts.ageMs);
    return { human, cookie: `trust_sess=${raw}` };
  }

  const post = (path: string, cookie?: string) =>
    h.app.request(path, { method: 'POST', headers: cookie ? { cookie } : {} });

  it('disable sets disabled_at and redirects to /account', async () => {
    const { human, cookie } = await signedIn();
    const r = await post('/account/disable', cookie);
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/account');
    expect((await h.store.getHumanById(human.id))?.disabled_at).toBeTruthy();
  });

  it('disable with no session redirects to /signin and mutates nothing', async () => {
    const r = await post('/account/disable');
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toContain('/signin');
  });

  it('enable with a FRESH session clears disabled_at', async () => {
    const { human, cookie } = await signedIn();
    await h.store.setHumanDisabled(human.id, true);
    const r = await post('/account/enable', cookie);
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/account');
    expect((await h.store.getHumanById(human.id))?.disabled_at).toBeNull();
  });

  it('enable with a STALE session is refused — redirects to /signin, stays disabled', async () => {
    // 10 min old > the 300s §7.5 freshness floor.
    const { human, cookie } = await signedIn({ ageMs: 10 * 60 * 1000 });
    await h.store.setHumanDisabled(human.id, true);
    const r = await post('/account/enable', cookie);
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toContain('/signin');
    // The kill-switch must NOT be reversible by a stale session.
    expect((await h.store.getHumanById(human.id))?.disabled_at).toBeTruthy();
  });
});
