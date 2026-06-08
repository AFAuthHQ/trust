import { describe, expect, it, beforeEach } from 'vitest';
import { createTestHarness, type TestHarness } from './helpers.js';

/**
 * trust.afauth.org went public without any crawler/agent-discovery
 * surface — no robots.txt, no llms.txt, no social card. These routes
 * (added in src/routes/seo.ts) close that gap so the attestor is
 * legible to search engines and the AI agents it actually serves.
 */
describe('SEO / discovery routes (robots, llms, sitemap, security.txt)', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  it('GET /robots.txt is served, welcomes AI crawlers, and points at the sitemap', async () => {
    const r = await h.app.request('/robots.txt');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('text/plain');
    const body = await r.text();
    expect(body).toContain('User-agent: GPTBot');
    expect(body).toContain('User-agent: ClaudeBot');
    expect(body).toMatch(/Sitemap: https?:\/\/\S+\/sitemap\.xml/);
    expect(body).toContain('Disallow: /admin/');
  });

  it('GET /llms.txt summarises the attestor and links the constellation', async () => {
    const r = await h.app.request('/llms.txt');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('text/markdown');
    const body = await r.text();
    expect(body).toContain('# trust.afauth.org');
    expect(body).toContain('https://afauth.org/llms.txt');
    expect(body).toContain('https://registry.afauth.org/llms.txt');
    expect(body).toContain('/.well-known/jwks.json');
    // No personal data in attestations is the whole point — state it for agents.
    expect(body).toContain('PII-free');
  });

  it('GET /sitemap.xml lists the public pages', async () => {
    const r = await h.app.request('/sitemap.xml');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('application/xml');
    const body = await r.text();
    expect(body).toMatch(/<loc>https?:\/\/[^<]+\/<\/loc>/);
    expect(body).toContain('/operator</loc>');
  });

  it('GET /.well-known/security.txt has the RFC 9116 required fields', async () => {
    const r = await h.app.request('/.well-known/security.txt');
    expect(r.status).toBe(200);
    const body = await r.text();
    expect(body).toContain('Contact: mailto:');
    expect(body).toContain('Expires:');
  });

  it('the landing page advertises the OG card and llms.txt for crawlers', async () => {
    const r = await h.app.request('/');
    const body = await r.text();
    expect(body).toContain('og:image');
    expect(body).toContain('https://afauth.org/og-trust.png');
    expect(body).toContain('twitter:card');
    expect(body).toContain('href="/llms.txt"');
  });
});
