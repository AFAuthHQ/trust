/**
 * E2E test-mode confirm endpoint.
 *
 * Gated behind TRUST_E2E_AUTOCONFIRM=1 / =true. In prod and in
 * any test where the gate isn't explicitly opened, the endpoint
 * MUST return 404 — there must be no path to confirming a link
 * request without the human's browser session, full stop.
 *
 * When the gate is open, the endpoint accepts { req_id, email },
 * upserts the human, marks them verified (so they can later
 * receive an `afauth-trust` attestation), and calls the same
 * confirmLinkRequest helper the browser /v1/link/confirm uses.
 * This unlocks scenarios 2 and 3 of spec/harness/e2e/ without
 * needing a Playwright browser harness.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  createAgentKeypair,
  createTestHarness,
  postJson,
  setTestEnv,
  type TestHarness,
} from './helpers.js';
import { resetConfigForTest } from '../src/lib/config.js';

async function startLink(h: TestHarness): Promise<{
  reqId: string;
  did: string;
}> {
  const kp = await createAgentKeypair();
  const r = await postJson(h.app, '/v1/link/start', {
    agent_did: kp.did,
    agent_pubkey_b64: kp.publicKeyB64,
    agent_label: 'e2e-agent',
  });
  expect(r.status).toBe(200);
  const body = (await r.json()) as { req_id: string };
  return { reqId: body.req_id, did: kp.did };
}

describe('POST /v1/link/confirm-e2e (gated test-mode auto-confirm)', () => {
  beforeEach(() => {
    setTestEnv();
    resetConfigForTest();
  });
  afterEach(() => {
    delete process.env.TRUST_E2E_AUTOCONFIRM;
    resetConfigForTest();
  });

  it('returns 404 when TRUST_E2E_AUTOCONFIRM is unset (default)', async () => {
    delete process.env.TRUST_E2E_AUTOCONFIRM;
    resetConfigForTest();
    const h = await createTestHarness();
    const { reqId } = await startLink(h);

    const r = await postJson(h.app, '/v1/link/confirm-e2e', {
      req_id: reqId,
      email: 'alice@example.com',
    });
    expect(r.status).toBe(404);
  });

  it('returns 404 when TRUST_E2E_AUTOCONFIRM=0', async () => {
    process.env.TRUST_E2E_AUTOCONFIRM = '0';
    resetConfigForTest();
    const h = await createTestHarness();
    const { reqId } = await startLink(h);

    const r = await postJson(h.app, '/v1/link/confirm-e2e', {
      req_id: reqId,
      email: 'alice@example.com',
    });
    expect(r.status).toBe(404);
  });

  it('auto-confirms a pending link when TRUST_E2E_AUTOCONFIRM=1', async () => {
    process.env.TRUST_E2E_AUTOCONFIRM = '1';
    resetConfigForTest();
    const h = await createTestHarness();
    const { reqId, did } = await startLink(h);

    const r = await postJson(h.app, '/v1/link/confirm-e2e', {
      req_id: reqId,
      email: 'alice@example.com',
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as {
      ok: boolean;
      binding_id: string;
      callback_url: string | null;
    };
    expect(body.ok).toBe(true);
    expect(body.binding_id).toMatch(/^[0-9a-f-]{36}$/);

    // The binding is real and queryable.
    const binding = await h.store.findActiveBindingByAgentDid(did);
    expect(binding).not.toBeNull();
    expect(binding!.agent_did).toBe(did);

    // The human was created and marked verified.
    const human = await h.store.getHumanByEmail('alice@example.com');
    expect(human).not.toBeNull();
    const verifications = await h.store.listVerifications(human!.id);
    expect(verifications.length).toBeGreaterThan(0);
  });

  it('also accepts TRUST_E2E_AUTOCONFIRM=true', async () => {
    process.env.TRUST_E2E_AUTOCONFIRM = 'true';
    resetConfigForTest();
    const h = await createTestHarness();
    const { reqId } = await startLink(h);

    const r = await postJson(h.app, '/v1/link/confirm-e2e', {
      req_id: reqId,
      email: 'alice@example.com',
    });
    expect(r.status).toBe(200);
  });

  it('rejects missing req_id or email', async () => {
    process.env.TRUST_E2E_AUTOCONFIRM = '1';
    resetConfigForTest();
    const h = await createTestHarness();

    const r1 = await postJson(h.app, '/v1/link/confirm-e2e', {
      email: 'alice@example.com',
    });
    expect(r1.status).toBe(400);

    const r2 = await postJson(h.app, '/v1/link/confirm-e2e', {
      req_id: 'aaaa',
    });
    expect(r2.status).toBe(400);
  });

  it('rejects a malformed email', async () => {
    process.env.TRUST_E2E_AUTOCONFIRM = '1';
    resetConfigForTest();
    const h = await createTestHarness();
    const { reqId } = await startLink(h);

    const r = await postJson(h.app, '/v1/link/confirm-e2e', {
      req_id: reqId,
      email: 'not-an-email',
    });
    expect(r.status).toBe(400);
  });

  it('rejects an unknown req_id', async () => {
    process.env.TRUST_E2E_AUTOCONFIRM = '1';
    resetConfigForTest();
    const h = await createTestHarness();

    const r = await postJson(h.app, '/v1/link/confirm-e2e', {
      req_id: '11111111-1111-1111-1111-111111111111',
      email: 'alice@example.com',
    });
    expect(r.status).toBe(404);
  });
});
