import { describe, expect, it, beforeEach } from 'vitest';
import { createTestHarness, type TestHarness } from './helpers.js';

describe('GET /.well-known/jwks.json', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  it('serves the public JWK with Ed25519 material only', async () => {
    const r = await h.app.request('/.well-known/jwks.json');
    expect(r.status).toBe(200);
    const body = (await r.json()) as { keys: Array<Record<string, string>> };
    expect(body.keys.length).toBe(1);
    const k = body.keys[0]!;
    expect(k.kty).toBe('OKP');
    expect(k.crv).toBe('Ed25519');
    expect(k.alg).toBe('EdDSA');
    expect(k.use).toBe('sig');
    expect(k.kid).toBeTruthy();
    // No private material leaked.
    expect(k.d).toBeUndefined();
  });

  it('cache-control is set for safe CDN caching', async () => {
    const r = await h.app.request('/.well-known/jwks.json');
    expect(r.headers.get('cache-control')).toContain('max-age=300');
  });
});
