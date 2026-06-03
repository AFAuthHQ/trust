import { describe, expect, it, beforeEach } from 'vitest';
import { importJWK, jwtVerify } from 'jose';
import { randomBytes } from 'node:crypto';
import {
  createAgentKeypair,
  createTestHarness,
  postJson,
  postMint,
  signMint,
  type TestHarness,
} from './helpers.js';
import { confirmLinkRequest } from '../src/lib/link-confirm.js';
import { listPublicJwks, ATTESTATION_JWT_ALG, ISS } from '../src/lib/signing.js';

/**
 * §3.1 keyless mint — the agent authenticates `/v1/token` by signing the
 * request per §5 with its account key; the attestor maps the verified
 * keyid to a binding. The keypair is the sole credential.
 */
describe('POST /v1/token — §3.1 keyless (signed) mint', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
    // ioredis-mock shares one store across instances — flush so a prior
    // test's (keyid, nonce) replay entries don't leak.
    await h.redis.flushall();
  });

  type Keypair = Awaited<ReturnType<typeof createAgentKeypair>>;

  async function setupLinked(opts: { email?: string } = {}): Promise<{ kp: Keypair; human: { id: string }; binding_id: string }> {
    const kp = await createAgentKeypair();
    const startResp = await postJson(h.app, '/v1/link/start', {
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
    });
    const { req_id } = (await startResp.json()) as { req_id: string };
    const human = await h.store.upsertHuman({ primary_email: opts.email ?? 'alice@example.com' });
    await h.store.recordVerification(human.id, 'email', 'magic-link');
    const confirmed = await confirmLinkRequest({ store: h.store, redis: h.redis, human, reqId: req_id });
    return { kp, human, binding_id: confirmed.binding_id };
  }

  async function code(r: Response): Promise<string> {
    return ((await r.json()) as { error: { code: string } }).error.code;
  }

  it('mints from a §5 signature alone — no binding_token — and the JWT binds to the signing key', async () => {
    const { kp, binding_id } = await setupLinked();
    const r = await postMint(h.app, kp.privateKey, kp.did, 'did:web:svc.example');
    expect(r.status).toBe(200);
    const { jwt, verification } = (await r.json()) as { jwt: string; verification: string };
    expect(verification).toBe('email');

    const jwks = await listPublicJwks(h.vault);
    const key = await importJWK(jwks.keys[0]!, ATTESTATION_JWT_ALG);
    const { payload } = await jwtVerify(jwt, key, {
      algorithms: [ATTESTATION_JWT_ALG],
      issuer: ISS,
      audience: 'did:web:svc.example',
    });
    expect(payload.sub).toBe(kp.did); // §10.2: attestation sub == request signer
    expect(payload.sub_h).toEqual(expect.stringMatching(/^[A-Za-z0-9_-]{22,86}$/));
    expect((await h.store.getBindingById(binding_id))?.last_used_at).toBeTruthy();
  });

  it('rejects a signature from a key that was never linked (401 unauthorized)', async () => {
    const kp = await createAgentKeypair(); // valid key, no binding
    const r = await postMint(h.app, kp.privateKey, kp.did, 'did:web:svc.example');
    expect(r.status).toBe(401);
    expect(await code(r)).toBe('unauthorized');
  });

  it('rejects a replayed (keyid, nonce) on the second mint', async () => {
    const { kp } = await setupLinked();
    const nonce = randomBytes(8).toString('hex');
    expect((await postMint(h.app, kp.privateKey, kp.did, 'did:web:svc.example', { nonce })).status).toBe(200);
    const replay = await postMint(h.app, kp.privateKey, kp.did, 'did:web:svc.example', { nonce });
    expect(replay.status).toBe(401);
    expect(await code(replay)).toBe('invalid_signature');
  });

  it('preserves the binding_revoked signal on the signed path (findLatestBindingByAgentDid)', async () => {
    const { kp, binding_id, human } = await setupLinked();
    await h.store.revokeBinding(binding_id, human.id);
    const r = await postMint(h.app, kp.privateKey, kp.did, 'did:web:svc.example');
    expect(r.status).toBe(403);
    expect(await code(r)).toBe('binding_revoked');
  });

  it('rejects a tampered body (content-digest mismatch)', async () => {
    const { kp } = await setupLinked();
    const signed = signMint(kp.privateKey, kp.did, 'did:web:svc.example');
    // Swap the body after signing; the digest header no longer matches.
    signed.body = JSON.stringify({ aud: 'did:web:evil.example' });
    const r = await h.app.request('/v1/token', { method: 'POST', headers: signed.headers, body: signed.body });
    expect(r.status).toBe(401);
    expect(await code(r)).toBe('invalid_signature');
  });

  it('rejects a signature whose @target-uri is a different host (cross-endpoint replay)', async () => {
    const { kp } = await setupLinked();
    const r = await postMint(h.app, kp.privateKey, kp.did, 'did:web:svc.example', {
      targetUri: 'https://evil.example.com/v1/token',
    });
    expect(r.status).toBe(401);
    expect(await code(r)).toBe('invalid_signature');
  });
});
