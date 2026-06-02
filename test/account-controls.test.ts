import { describe, expect, it, beforeEach } from 'vitest';
import { createTestHarness, type TestHarness } from './helpers.js';
import { generateToken, hashToken } from '../src/lib/tokens.js';

describe('account kill-switch controls (/account/pause, /account/resume)', () => {
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

  it('pause sets paused_at and redirects to /account', async () => {
    const { human, cookie } = await signedIn();
    const r = await post('/account/pause', cookie);
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/account');
    expect((await h.store.getHumanById(human.id))?.paused_at).toBeTruthy();
  });

  it('pause with no session redirects to /signin and mutates nothing', async () => {
    const r = await post('/account/pause');
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toContain('/signin');
  });

  it('resume with a FRESH session clears paused_at', async () => {
    const { human, cookie } = await signedIn();
    await h.store.setHumanPaused(human.id, true);
    const r = await post('/account/resume', cookie);
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/account');
    expect((await h.store.getHumanById(human.id))?.paused_at).toBeNull();
  });

  it('resume with a STALE session is refused — redirects to /signin, stays paused', async () => {
    // 10 min old > the 300s §7.5 freshness floor.
    const { human, cookie } = await signedIn({ ageMs: 10 * 60 * 1000 });
    await h.store.setHumanPaused(human.id, true);
    const r = await post('/account/resume', cookie);
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toContain('/signin');
    // The kill-switch must NOT be reversible by a stale session.
    expect((await h.store.getHumanById(human.id))?.paused_at).toBeTruthy();
  });

  // ---- owner-facing wording: "Pause/Resume", not "Disable/Re-enable" ----
  // The owner self-service kill-switch is framed as a reversible "pause".
  // The operator take-down on /policy deliberately keeps "Disable account"
  // (different actor, different intent) — asserted in operator-policy.test.

  const getAccount = (cookie: string) =>
    h.app.request('/account', { headers: { cookie } });

  it('active account renders the Pause control, not "Disable"/"Re-enable"', async () => {
    const { cookie } = await signedIn();
    const body = await (await getAccount(cookie)).text();
    expect(body).toContain('Pause all agents');
    expect(body).toContain('You can resume anytime');
    expect(body).not.toContain('Disable account');
    expect(body).not.toContain('Re-enable');
  });

  it('paused account renders "Paused" status + a Resume control', async () => {
    const { human, cookie } = await signedIn();
    await h.store.setHumanPaused(human.id, true);
    const body = await (await getAccount(cookie)).text();
    expect(body).toContain('>Paused<');
    expect(body).toContain('>Resume<');
    expect(body).not.toContain('Re-enable account');
  });
});
