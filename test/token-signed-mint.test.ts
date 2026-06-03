import { describe, expect, it, beforeEach } from 'vitest';
import { importJWK, jwtVerify } from 'jose';
import { createHash, randomBytes, sign as cryptoSign, type KeyObject } from 'node:crypto';
import { createAgentKeypair, createTestHarness, postJson, type TestHarness } from './helpers.js';
import { confirmLinkRequest } from '../src/lib/link-confirm.js';
import { listPublicJwks, ATTESTATION_JWT_ALG, ISS } from '../src/lib/signing.js';

/**
 * §3.1 keyless mint — the agent authenticates `/v1/token` by signing the
 * request per §5 with its account key, instead of presenting a bearer
 * `binding_token`. The attestor maps the verified `keyid` to a binding.
 *
 * PUBLIC_BASE_URL in tests is http://localhost:3001 (helpers.setTestEnv),
 * so that is the canonical @target-uri the route reconstructs and the
 * agent must sign.
 */
const TOKEN_URL = 'http://localhost:3001/v1/token';

function signMint(
  priv: KeyObject,
  did: string,
  aud: string,
  over: { nonce?: string; targetUri?: string; created?: number; body?: string } = {},
): { body: string; headers: Record<string, string> } {
  const body = over.body ?? JSON.stringify({ aud });
  const targetUri = over.targetUri ?? TOKEN_URL;
  const created = over.created ?? Math.floor(Date.now() / 1000);
  const expires = created + 60;
  const nonce = over.nonce ?? randomBytes(8).toString('hex');
  const digest = `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
  const sigParams =
    `created=${created};expires=${expires};nonce="${nonce}";keyid="${did}";alg="ed25519"`;
  const canonical =
    `"@method": POST\n` +
    `"@target-uri": ${targetUri}\n` +
    `"content-digest": ${digest}\n` +
    `"@signature-params": ("@method" "@target-uri" "content-digest");${sigParams}`;
  const sig = cryptoSign(null, Buffer.from(canonical, 'utf8'), priv);
  return {
    body,
    headers: {
      'content-type': 'application/json',
      'content-digest': digest,
      'signature-input': `sig1=("@method" "@target-uri" "content-digest");${sigParams}`,
      signature: `sig1=:${Buffer.from(sig).toString('base64')}:`,
    },
  };
}

function postSigned(h: TestHarness, signed: { body: string; headers: Record<string, string> }) {
  return h.app.request('/v1/token', {
    method: 'POST',
    headers: signed.headers,
    body: signed.body,
  });
}

async function code(r: Response): Promise<string> {
  return ((await r.json()) as { error: { code: string } }).error.code;
}

describe('POST /v1/token — §3.1 keyless (signed) mint', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
    // ioredis-mock shares an in-memory store across instances; flush so a
    // prior test's (keyid, nonce) replay entries don't leak.
    await h.redis.flushall();
  });

  async function setupLinked(opts: { email?: string } = {}) {
    const kp = await createAgentKeypair();
    const startResp = await postJson(h.app, '/v1/link/start', {
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
    });
    const { req_id } = (await startResp.json()) as { req_id: string };
    const human = await h.store.upsertHuman({ primary_email: opts.email ?? 'alice@example.com' });
    await h.store.recordVerification(human.id, 'email', 'magic-link');
    const confirmed = await confirmLinkRequest({ store: h.store, redis: h.redis, human, reqId: req_id });
    return { kp, human, binding_id: confirmed.binding_id, binding_token: confirmed.binding_token };
  }

  it('mints from a §5 signature alone — no binding_token — and the JWT binds to the signing key', async () => {
    const { kp, binding_id } = await setupLinked();
    const r = await postSigned(h, signMint(kp.privateKey, kp.did, 'did:web:svc.example'));
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

    // last_used_at bumped, same as the bearer path.
    expect((await h.store.getBindingById(binding_id))?.last_used_at).toBeTruthy();
  });

  it('dual-accept: the same binding mints via BOTH a signature and a legacy Bearer token', async () => {
    const { kp, binding_token } = await setupLinked();
    const viaSig = await postSigned(h, signMint(kp.privateKey, kp.did, 'did:web:svc.example'));
    expect(viaSig.status).toBe(200);
    const viaBearer = await postJson(
      h.app,
      '/v1/token',
      { aud: 'did:web:svc.example' },
      { headers: { authorization: `Bearer ${binding_token}` } },
    );
    expect(viaBearer.status).toBe(200);
  });

  it('rejects a signature from a key that was never linked (401 unauthorized)', async () => {
    const kp = await createAgentKeypair(); // valid key, no binding
    const r = await postSigned(h, signMint(kp.privateKey, kp.did, 'did:web:svc.example'));
    expect(r.status).toBe(401);
    expect(await code(r)).toBe('unauthorized');
  });

  it('rejects a replayed (keyid, nonce) on the second mint', async () => {
    const { kp } = await setupLinked();
    const nonce = randomBytes(8).toString('hex');
    const first = await postSigned(h, signMint(kp.privateKey, kp.did, 'did:web:svc.example', { nonce }));
    expect(first.status).toBe(200);
    const replay = await postSigned(h, signMint(kp.privateKey, kp.did, 'did:web:svc.example', { nonce }));
    expect(replay.status).toBe(401);
    expect(await code(replay)).toBe('invalid_signature');
  });

  it('preserves the binding_revoked signal on the signed path (findLatestBindingByAgentDid)', async () => {
    const { kp, binding_id, human } = await setupLinked();
    await h.store.revokeBinding(binding_id, human.id);
    const r = await postSigned(h, signMint(kp.privateKey, kp.did, 'did:web:svc.example'));
    expect(r.status).toBe(403);
    expect(await code(r)).toBe('binding_revoked');
  });

  it('rejects a tampered body (content-digest mismatch)', async () => {
    const { kp } = await setupLinked();
    const signed = signMint(kp.privateKey, kp.did, 'did:web:svc.example');
    // Swap the body after signing; the digest header no longer matches.
    signed.body = JSON.stringify({ aud: 'did:web:evil.example' });
    const r = await postSigned(h, signed);
    expect(r.status).toBe(401);
    expect(await code(r)).toBe('invalid_signature');
  });

  it('rejects a signature whose @target-uri is a different host (cross-endpoint replay)', async () => {
    const { kp } = await setupLinked();
    const signed = signMint(kp.privateKey, kp.did, 'did:web:svc.example', {
      targetUri: 'https://evil.example.com/v1/token',
    });
    const r = await postSigned(h, signed);
    expect(r.status).toBe(401);
    expect(await code(r)).toBe('invalid_signature');
  });
});
