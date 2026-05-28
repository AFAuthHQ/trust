import { beforeEach, describe, expect, it } from 'vitest';
import { createTestHarness, type TestHarness } from './helpers.js';

describe('signin UX — contextual copy + inbox self-heal', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  describe('GET /signin contextual copy', () => {
    // Test harness has no GOOGLE_OAUTH_CLIENT_ID, so the email-only
    // branch renders. Assert headline + presence/absence of the
    // link-context lede.

    it('renders generic copy when no next param', async () => {
      const r = await h.app.request('/signin');
      expect(r.status).toBe(200);
      const body = await r.text();
      expect(body).toContain('<h1>Sign in</h1>');
      expect(body).not.toContain('link your agent');
      expect(body).not.toContain('create your AFAuth account if this is your first time');
    });

    it('renders link-context copy when next starts with /link?', async () => {
      const r = await h.app.request(
        '/signin?next=' + encodeURIComponent('/link?req=abc.def'),
      );
      expect(r.status).toBe(200);
      const body = await r.text();
      expect(body).toContain('Sign in to link your agent');
      // Hono html-escapes ' → &#39;, hence the entity match.
      expect(body).toContain('create your AFAuth account if this is your first time');
    });

    it('does NOT trigger link-context copy for /linkfoo or other prefixes', async () => {
      const r = await h.app.request('/signin?next=' + encodeURIComponent('/linkable'));
      expect(r.status).toBe(200);
      const body = await r.text();
      expect(body).toContain('<h1>Sign in</h1>');
      expect(body).not.toContain('link your agent');
      expect(body).not.toContain('create your AFAuth account if this is your first time');
    });
  });

  describe('GET /auth/session', () => {
    it('returns {authenticated:false} when no session cookie', async () => {
      const r = await h.app.request('/auth/session');
      expect(r.status).toBe(200);
      expect(r.headers.get('cache-control')).toBe('no-store');
      expect(await r.json()).toEqual({ authenticated: false });
    });

    it('returns {authenticated:true} once a session cookie is present', async () => {
      // Plant a session directly so we don't depend on the magic-link flow.
      const human = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
      const { generateToken, hashToken } = await import('../src/lib/tokens.js');
      const raw = generateToken();
      await h.store.createSession(
        human.id,
        hashToken(raw),
        new Date(Date.now() + 60 * 1000),
      );
      const r = await h.app.request('/auth/session', {
        headers: { cookie: `trust_sess=${raw}` },
      });
      expect(r.status).toBe(200);
      expect(await r.json()).toEqual({ authenticated: true });
    });
  });

  describe('POST /signin → Check your inbox page', () => {
    it('embeds the inbox-poll script with data-next when next is supplied', async () => {
      const r = await h.app.request('/signin', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          email: 'alice@example.com',
          next: '/link?req=abc.def',
        }).toString(),
      });
      expect(r.status).toBe(200);
      const body = await r.text();
      expect(body).toContain('Check your inbox');
      expect(body).toContain('src="/inbox-poll.js"');
      expect(body).toContain('data-next="/link?req=abc.def"');
    });

    it('falls back to /account in data-next when next is missing', async () => {
      const r = await h.app.request('/signin', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ email: 'alice@example.com' }).toString(),
      });
      expect(r.status).toBe(200);
      const body = await r.text();
      expect(body).toContain('data-next="/account"');
    });

    it('refuses an off-origin next, falling back to /account', async () => {
      const r = await h.app.request('/signin', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          email: 'alice@example.com',
          next: '//evil.example/path',
        }).toString(),
      });
      expect(r.status).toBe(200);
      const body = await r.text();
      expect(body).toContain('data-next="/account"');
      expect(body).not.toContain('evil.example');
    });
  });
});
