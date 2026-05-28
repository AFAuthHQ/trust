import { describe, expect, it } from 'vitest';
import { createTestHarness } from './helpers.js';

describe('GET /favicon.svg — same-origin', () => {
  it('serves the bundled favicon from trust/public', async () => {
    const h = await createTestHarness();
    const r = await h.app.request('/favicon.svg');
    expect(r.status).toBe(200);
    const body = await r.text();
    expect(body).toContain('<svg');
    // Sanity: the AFAuth mark uses these specific shapes.
    expect(body.length).toBeGreaterThan(50);
  });

  it('the landing page links to the same-origin favicon, not the apex', async () => {
    const h = await createTestHarness();
    const r = await h.app.request('/');
    const body = await r.text();
    expect(body).toContain('href="/favicon.svg"');
    expect(body).not.toContain('https://afauth.org/favicon.svg');
  });
});
