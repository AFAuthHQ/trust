/**
 * Pre-public hardening: request body-size limit (memory-exhaustion DoS
 * guard). Every write handler buffers the body before zod runs.
 */
import { describe, expect, it } from 'vitest';
import { createTestHarness } from './helpers.js';

describe('request body-size limit', () => {
  it('rejects an oversized request body with 413', async () => {
    const h = await createTestHarness();
    const huge = 'a'.repeat(300 * 1024); // ~300 KB, over the 256 KB cap
    const res = await h.app.request('/v1/link/start', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ agent_did: 'did:key:z6Mk', agent_pubkey_b64: huge }),
    });
    expect(res.status).toBe(413);
  });

  it('still accepts a normally-sized request body', async () => {
    const h = await createTestHarness();
    // Invalid key on purpose — we only assert it is NOT rejected as 413;
    // a small body reaches the handler and fails validation instead.
    const res = await h.app.request('/v1/link/start', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ agent_did: 'did:key:zInvalid', agent_pubkey_b64: 'AAAA' }),
    });
    expect(res.status).not.toBe(413);
  });
});
