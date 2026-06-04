/**
 * Pre-public hardening: CSRF protection on cookie-authenticated,
 * state-changing routes. SameSite=Lax alone leaves a cross-subdomain
 * gap (any *.afauth.org origin is same-site) and is a single point of
 * failure; this adds an explicit Origin / Sec-Fetch-Site check.
 *
 * The agent JSON API (application/json) is intentionally NOT guarded by
 * this middleware — those callers are non-browser and carry no ambient
 * cookies; cross-origin application/json is already blocked by the
 * absence of CORS (browser preflight fails).
 */
import { describe, expect, it, beforeEach } from 'vitest';
import { createTestHarness, type TestHarness } from './helpers.js';
import { generateToken, hashToken } from '../src/lib/tokens.js';

describe('CSRF protection on state-changing form routes', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  async function signedIn() {
    const human = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
    const raw = generateToken();
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await h.store.createSession(human.id, hashToken(raw), expires);
    return { human, cookie: `trust_sess=${raw}` };
  }

  it('rejects a cross-site form POST carrying a valid session cookie (403, no mutation)', async () => {
    const { human, cookie } = await signedIn();
    const r = await h.app.request('/account/pause', {
      method: 'POST',
      headers: {
        cookie,
        origin: 'https://evil.example',
        'content-type': 'application/x-www-form-urlencoded',
      },
    });
    expect(r.status).toBe(403);
    // The kill-switch must not have flipped.
    expect((await h.store.getHumanById(human.id))?.paused_at).toBeFalsy();
  });

  it('allows a same-origin form POST (Sec-Fetch-Site: same-origin)', async () => {
    const { human, cookie } = await signedIn();
    const r = await h.app.request('/account/pause', {
      method: 'POST',
      headers: {
        cookie,
        'sec-fetch-site': 'same-origin',
        'content-type': 'application/x-www-form-urlencoded',
      },
    });
    expect(r.status).toBe(302);
    expect((await h.store.getHumanById(human.id))?.paused_at).toBeTruthy();
  });

  it('does NOT block the agent JSON API (application/json, no Origin)', async () => {
    const r = await h.app.request('/v1/link/start', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ agent_did: 'did:key:zInvalid', agent_pubkey_b64: 'AAAA' }),
    });
    // Reaches the handler (fails validation) rather than being CSRF-rejected.
    expect(r.status).not.toBe(403);
  });

  it('closes the text/plain bypass on the JSON confirm endpoint', async () => {
    const { cookie } = await signedIn();
    const r = await h.app.request('/v1/link/confirm', {
      method: 'POST',
      headers: {
        cookie,
        origin: 'https://evil.example',
        'content-type': 'text/plain',
      },
      body: JSON.stringify({ req_id: 'whatever' }),
    });
    expect(r.status).toBe(403);
  });
});
