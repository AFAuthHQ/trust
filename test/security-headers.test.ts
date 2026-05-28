import { describe, expect, it, beforeEach } from 'vitest';
import { createTestHarness, type TestHarness } from './helpers.js';

describe('security response headers', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  it('applies HSTS, frame deny, nosniff, referrer, permissions, CSP to HTML', async () => {
    const r = await h.app.request('/');
    expect(r.headers.get('strict-transport-security')).toMatch(
      /max-age=\d+;\s*includeSubDomains;\s*preload/,
    );
    expect(r.headers.get('x-content-type-options')).toBe('nosniff');
    expect(r.headers.get('x-frame-options')).toBe('DENY');
    expect(r.headers.get('referrer-policy')).toBe('strict-origin-when-cross-origin');
    expect(r.headers.get('permissions-policy')).toMatch(/camera=\(\)/);
    const csp = r.headers.get('content-security-policy') ?? '';
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("form-action 'self'");
    expect(csp).toContain("base-uri 'self'");
  });

  it('applies headers to JSON API responses too', async () => {
    const r = await h.app.request('/healthz');
    expect(r.headers.get('strict-transport-security')).toBeTruthy();
    expect(r.headers.get('x-content-type-options')).toBe('nosniff');
    expect(r.headers.get('content-security-policy')).toBeTruthy();
  });

  it('applies headers to JWKS', async () => {
    const r = await h.app.request('/.well-known/jwks.json');
    expect(r.headers.get('strict-transport-security')).toBeTruthy();
    expect(r.headers.get('cache-control')).toContain('max-age=300');
  });

  it('CSP forbids script-src unsafe-inline (no inline scripts in any view)', async () => {
    const r = await h.app.request('/');
    const csp = r.headers.get('content-security-policy') ?? '';
    // script-src is restricted to 'self' only — any inline <script>
    // injected later will trip CSP in the browser. This test catches
    // accidental reintroduction of inline scripts at the policy
    // level, before they hit a real browser.
    expect(csp).toMatch(/script-src 'self'(?!\s*'unsafe-inline')/);
  });

  it('CSP img-src is same-origin (no cross-origin image hosts)', async () => {
    const r = await h.app.request('/');
    const csp = r.headers.get('content-security-policy') ?? '';
    // After the favicon was brought in-house under /favicon.svg, the
    // CSP no longer needs to allow https://afauth.org. Catching any
    // re-introduction of a cross-origin image host before it ships.
    expect(csp).toContain("img-src 'self' data:");
    expect(csp).not.toContain('afauth.org');
  });
});
