import { describe, expect, it, beforeEach } from 'vitest';
import { createTestHarness, type TestHarness } from './helpers.js';

describe('/operator and /policy pages', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  it('/operator renders with the AFAP-0006 commitment text', async () => {
    const r = await h.app.request('/operator');
    expect(r.status).toBe(200);
    const body = await r.text();
    expect(body).toContain('Operator commitment');
    expect(body).toContain('AFAP-0006');
    expect(body).toContain('[email protected]');
    expect(body).toContain('[email protected]');
    // Frames AFAP-0006's anti-PII guarantee.
    expect(body).toContain('personal data');
    // Promises the 900s grace pre-publication.
    expect(body).toContain('900');
  });

  it('/policy renders with category list + revoke vs disable distinction', async () => {
    const r = await h.app.request('/policy');
    expect(r.status).toBe(200);
    const body = await r.text();
    expect(body).toContain('Take-down policy');
    expect(body).toContain('Revoke binding');
    expect(body).toContain('Disable account');
    expect(body).toContain('15 minutes'); // revocation latency bound
    expect(body).toContain('[email protected]');
  });

  it('the layout nav links to /operator and /policy on every page', async () => {
    const home = await (await h.app.request('/')).text();
    expect(home).toContain('href="/operator"');
    expect(home).toContain('href="/policy"');

    const op = await (await h.app.request('/operator')).text();
    expect(op).toContain('href="/policy"');
  });
});
