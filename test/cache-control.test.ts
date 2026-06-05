import { beforeEach, describe, expect, it } from 'vitest';
import { createTestHarness, type TestHarness } from './helpers.js';

/**
 * Authenticated / PII-bearing HTML (the account dashboard, the magic-link
 * consent page, the deep-link confirm page) must not be stored by shared
 * proxies or the browser disk cache. Public marketing pages and the JWKS
 * stay cacheable.
 */
describe('Cache-Control: no-store on sensitive pages', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  it('GET /account sets no-store (even on the unauthenticated redirect)', async () => {
    const r = await h.app.request('/account', { redirect: 'manual' });
    expect(r.headers.get('cache-control')).toBe('no-store');
  });

  it('GET /signin/callback sets no-store', async () => {
    const r = await h.app.request('/signin/callback'); // no token → error page
    expect(r.headers.get('cache-control')).toBe('no-store');
  });

  it('GET /link sets no-store', async () => {
    const r = await h.app.request('/link'); // no req → error page
    expect(r.headers.get('cache-control')).toBe('no-store');
  });

  it('public landing page is not forced no-store', async () => {
    const r = await h.app.request('/');
    expect(r.headers.get('cache-control')).not.toBe('no-store');
  });
});
