import { beforeEach, describe, expect, it } from 'vitest';
import {
  createAgentKeypair,
  createTestHarness,
  postJson,
  type TestHarness,
} from './helpers.js';

/**
 * /v1/link/start accepts an optional loopback `callback_url` that the
 * "Linked." page later reflects into an <a href>. The server must
 * validate the URL SCHEME, not just the host — `new URL(...).hostname`
 * is `localhost` for `javascript://localhost/…`, `https://localhost/…`,
 * `ftp://localhost/…`, so a host-only check lets non-http schemes
 * through. Only `http://` on a loopback host is ever legitimate (desktop
 * CLIs serve plain http on 127.0.0.1 / localhost).
 */
describe('POST /v1/link/start — callback_url scheme validation', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  async function start(callback_url: string): Promise<Response> {
    const kp = await createAgentKeypair();
    return postJson(h.app, '/v1/link/start', {
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
      callback_url,
    });
  }

  it('rejects a javascript: URL whose authority is a loopback host', async () => {
    const r = await start('javascript://localhost/%0aalert(document.domain)');
    expect(r.status).toBe(400);
  });

  it('rejects https:// even on a loopback host', async () => {
    expect((await start('https://localhost:3000/cb')).status).toBe(400);
    expect((await start('https://127.0.0.1:3000/cb')).status).toBe(400);
  });

  it('rejects other schemes and non-loopback hosts', async () => {
    expect((await start('ftp://localhost/x')).status).toBe(400);
    expect((await start('http://evil.example/cb')).status).toBe(400);
  });

  it('still accepts a plain http loopback callback', async () => {
    expect((await start('http://127.0.0.1:53219/done')).status).toBe(200);
    expect((await start('http://localhost:53219/done')).status).toBe(200);
  });
});
