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
    // Content Signals (contentsignals.org): AFAuth opts INTO every AI use —
    // the permissive stance is the whole point of an agent-first protocol.
    expect(body).toMatch(/Content-Signal:.*search=yes/);
    expect(body).toMatch(/Content-Signal:.*ai-input=yes/);
    expect(body).toMatch(/Content-Signal:.*ai-train=yes/);
  });

  it('advertises the llms.txt markdown index via an RFC 8288 Link header', async () => {
    const r = await h.app.request('/');
    const link = r.headers.get('link');
    expect(link).toContain('/llms.txt');
    expect(link).toContain('rel="alternate"');
    expect(link).toContain('text/markdown');
  });

  it('GET / serves Markdown when the client asks for text/markdown', async () => {
    const r = await h.app.request('/', { headers: { accept: 'text/markdown' } });
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('text/markdown');
    // Vary: Accept so a shared cache keys the two representations apart.
    expect(r.headers.get('vary')).toMatch(/accept/i);
    const body = await r.text();
    expect(body).toContain('# trust.afauth.org');
    expect(body).toContain('PII-free');
    // Must be the markdown view, not the HTML landing page.
    expect(body).not.toContain('og:image');
  });

  it('GET / falls through to HTML for browsers (no Accept: text/markdown)', async () => {
    const r = await h.app.request('/');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type')).toContain('text/html');
    expect(await r.text()).toContain('og:image');
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
