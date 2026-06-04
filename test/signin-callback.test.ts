import { beforeEach, describe, expect, it } from 'vitest';
import { createTestHarness, type TestHarness } from './helpers.js';
import { generateToken, hashToken } from '../src/lib/tokens.js';

describe('GET /signin/callback — consent page (pre-fetch resistant)', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  async function seedToken(email = 'alice@example.com', next?: string) {
    const raw = generateToken();
    await h.store.createMagicLink(
      email,
      hashToken(raw),
      new Date(Date.now() + 15 * 60 * 1000),
      next,
    );
    return raw;
  }

  it('renders the consent page when the token is valid', async () => {
    const raw = await seedToken();
    const r = await h.app.request(`/signin/callback?token=${encodeURIComponent(raw)}`);
    expect(r.status).toBe(200);
    const body = await r.text();
    expect(body).toContain('Sign in to AFAuth');
    expect(body).toContain('alice@example.com');
    expect(body).toContain('action="/signin/callback"');
    expect(body).toContain('type="hidden" name="token"');
  });

  it('multiple GETs do NOT burn the token (pre-fetch defence)', async () => {
    const raw = await seedToken();
    // Simulate Microsoft SafeLinks / Gmail spam scanner / browser
    // prefetch — multiple GETs to the link.
    const r1 = await h.app.request(`/signin/callback?token=${encodeURIComponent(raw)}`);
    const r2 = await h.app.request(`/signin/callback?token=${encodeURIComponent(raw)}`);
    const r3 = await h.app.request(`/signin/callback?token=${encodeURIComponent(raw)}`);
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);
    expect(r3.status).toBe(200);

    // Token still consumable via POST after all the GETs.
    const post = await h.app.request('/signin/callback', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' },
      body: `token=${encodeURIComponent(raw)}`,
    });
    expect(post.status).toBe(302);
    expect(post.headers.get('location')).toBe('/account');
  });

  it('returns 410 + recovery page when the token has been consumed', async () => {
    const raw = await seedToken();
    // Consume via POST.
    await h.app.request('/signin/callback', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' },
      body: `token=${encodeURIComponent(raw)}`,
    });
    // GET now shows the recovery page.
    const r = await h.app.request(`/signin/callback?token=${encodeURIComponent(raw)}`);
    expect(r.status).toBe(410);
    const body = await r.text();
    expect(body).toContain('Link unavailable');
    expect(body).toContain('expired or was already used');
    expect(body).toContain('href="/signin"'); // recovery CTA
  });

  it('returns 410 when the token has expired', async () => {
    const raw = generateToken();
    await h.store.createMagicLink(
      'alice@example.com',
      hashToken(raw),
      new Date(Date.now() - 1000), // already expired
    );
    const r = await h.app.request(`/signin/callback?token=${encodeURIComponent(raw)}`);
    expect(r.status).toBe(410);
  });

  it('returns 400 when no token is supplied', async () => {
    const r = await h.app.request('/signin/callback');
    expect(r.status).toBe(400);
    expect(await r.text()).toContain('No sign-in token supplied');
  });

  it('returns 410 for a token that was never issued', async () => {
    const r = await h.app.request('/signin/callback?token=does-not-exist');
    expect(r.status).toBe(410);
  });
});

describe('POST /signin/callback — atomic consume', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  it('consumes the token, creates a human + email verification, sets session, redirects to /account', async () => {
    const raw = generateToken();
    await h.store.createMagicLink(
      'bob@example.com',
      hashToken(raw),
      new Date(Date.now() + 15 * 60 * 1000),
    );
    const r = await h.app.request('/signin/callback', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' },
      body: `token=${encodeURIComponent(raw)}`,
    });
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/account');
    // Set-Cookie present, HttpOnly.
    const cookie = r.headers.get('set-cookie');
    expect(cookie).toMatch(/trust_sess=/);
    expect(cookie?.toLowerCase()).toContain('httponly');

    // Human exists with the email verification recorded.
    const human = await h.store.getHumanByEmail('bob@example.com');
    expect(human).not.toBeNull();
    const verifications = await h.store.listVerifications(human!.id);
    expect(verifications.map((v) => v.method)).toContain('email');
  });

  it('a second POST with the same token returns 410 (single-use)', async () => {
    const raw = generateToken();
    await h.store.createMagicLink(
      'eve@example.com',
      hashToken(raw),
      new Date(Date.now() + 15 * 60 * 1000),
    );
    const first = await h.app.request('/signin/callback', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' },
      body: `token=${encodeURIComponent(raw)}`,
    });
    expect(first.status).toBe(302);
    const second = await h.app.request('/signin/callback', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' },
      body: `token=${encodeURIComponent(raw)}`,
    });
    expect(second.status).toBe(410);
  });

  it('honours the `next` path when consuming', async () => {
    const raw = generateToken();
    await h.store.createMagicLink(
      'next@example.com',
      hashToken(raw),
      new Date(Date.now() + 15 * 60 * 1000),
      '/link?req=opaque-jwt-here',
    );
    const r = await h.app.request('/signin/callback', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', 'sec-fetch-site': 'same-origin' },
      body: `token=${encodeURIComponent(raw)}`,
    });
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/link?req=opaque-jwt-here');
  });
});
