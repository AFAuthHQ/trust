import { describe, expect, it, beforeEach } from 'vitest';
import { importJWK, jwtVerify } from 'jose';
import {
  createAgentKeypair,
  createTestHarness,
  postJson,
  postMint,
  type TestHarness,
} from './helpers.js';
import { confirmLinkRequest } from '../src/lib/link-confirm.js';
import { listPublicJwks, ATTESTATION_JWT_ALG, ISS } from '../src/lib/signing.js';

/**
 * §10 attestation issuance via §3.1 keyless mint: the agent authenticates
 * `/v1/token` by signing the request with its account key (no bearer
 * token). These tests pin the issuance *policy* (verification ranking,
 * sub_h, quota, the revoke/pause kill-switch). The signature mechanics +
 * replay live in `request-sig.test.ts` and `token-signed-mint.test.ts`.
 */
describe('POST /v1/token — §10 attestation issuance (keyless mint)', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
    // ioredis-mock shares one store across instances; flush so prior
    // (keyid, nonce) replay entries and quota counters don't leak.
    await h.redis.flushall();
  });

  type Keypair = Awaited<ReturnType<typeof createAgentKeypair>>;
  const mint = (kp: Keypair, aud: string) => postMint(h.app, kp.privateKey, kp.did, aud);

  async function setupLinked(
    opts: {
      email?: string;
      verifications?: Array<{ method: 'email' | 'oauth' | 'payment'; provider: string }>;
    } = {},
  ) {
    const kp = await createAgentKeypair();
    const startResp = await postJson(h.app, '/v1/link/start', {
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
    });
    const { req_id } = (await startResp.json()) as { req_id: string };
    const human = await h.store.upsertHuman({ primary_email: opts.email ?? 'alice@example.com' });
    for (const v of opts.verifications ?? [{ method: 'email', provider: 'magic-link' }]) {
      await h.store.recordVerification(human.id, v.method, v.provider);
    }
    const confirmed = await confirmLinkRequest({ store: h.store, redis: h.redis, human, reqId: req_id });
    return { kp, human, agentDid: kp.did, binding_id: confirmed.binding_id };
  }

  it('mints a JWT that verifies offline against the JWKS', async () => {
    const { kp, binding_id, agentDid } = await setupLinked();
    const r = await mint(kp, 'did:web:svc.example');
    expect(r.status).toBe(200);
    const body = (await r.json()) as { jwt: string; expires_at: number; verification: string };
    expect(body.verification).toBe('email');

    const jwks = await listPublicJwks(h.vault);
    const key = await importJWK(jwks.keys[0]!, ATTESTATION_JWT_ALG);
    const { payload } = await jwtVerify(body.jwt, key, {
      algorithms: [ATTESTATION_JWT_ALG],
      issuer: ISS,
      audience: 'did:web:svc.example',
    });
    expect(payload.sub).toBe(agentDid);
    expect(payload.verification).toBe('email');
    expect(payload.sub_h).toEqual(expect.stringMatching(/^[A-Za-z0-9_-]{22,86}$/));
    expect(payload.sub_h).not.toBe(payload.sub);
    expect(payload.sub_h).not.toBe(payload.aud);

    const refreshed = await h.store.getBindingById(binding_id);
    expect(refreshed?.last_used_at).toBeTruthy();
  });

  it('slides the binding expiry forward on each successful mint (inactivity window)', async () => {
    const { kp, binding_id } = await setupLinked();
    // Simulate a binding partway through its life: expiry only 2 days out.
    const bnd = await h.store.getBindingById(binding_id);
    if (!bnd) throw new Error('binding not found');
    const before = Date.now() + 2 * 24 * 60 * 60 * 1000;
    bnd.expires_at = new Date(before);

    expect((await mint(kp, 'did:web:svc.example')).status).toBe(200);

    // Re-armed to ~now + 90d, well beyond the 2-day mark it sat at.
    const refreshed = await h.store.getBindingById(binding_id);
    expect(refreshed!.expires_at.getTime()).toBeGreaterThan(before);
    expect(refreshed!.expires_at.getTime()).toBeGreaterThan(
      Date.now() + 89 * 24 * 60 * 60 * 1000,
    );
  });

  it('returns binding_expires_at in the mint response, reflecting the slid expiry', async () => {
    const { kp } = await setupLinked();
    const r = await mint(kp, 'did:web:svc.example');
    expect(r.status).toBe(200);
    const body = (await r.json()) as { binding_expires_at: number };
    expect(body.binding_expires_at).toBeGreaterThan(
      Math.floor(Date.now() / 1000) + 89 * 24 * 60 * 60,
    );
  });

  it('requires a signed request — an unsigned POST is rejected', async () => {
    const r = await postJson(h.app, '/v1/token', { aud: 'did:web:svc.example' });
    expect(r.status).toBe(401);
  });

  it('emits the strongest verification (payment > oauth > email)', async () => {
    const { kp } = await setupLinked({
      verifications: [
        { method: 'email', provider: 'magic-link' },
        { method: 'oauth', provider: 'github' },
        { method: 'payment', provider: 'stripe' },
      ],
    });
    const r = await mint(kp, 'did:web:svc.example');
    expect(((await r.json()) as { verification: string }).verification).toBe('payment');
  });

  it('falls back to email when stronger methods are absent', async () => {
    const { kp } = await setupLinked({ verifications: [{ method: 'email', provider: 'magic-link' }] });
    const r = await mint(kp, 'did:web:svc.example');
    expect(((await r.json()) as { verification: string }).verification).toBe('email');
  });

  it('refuses if the human has no verifications on file', async () => {
    const kp = await createAgentKeypair();
    const startResp = await postJson(h.app, '/v1/link/start', {
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
    });
    const { req_id } = (await startResp.json()) as { req_id: string };
    const human = await h.store.upsertHuman({ primary_email: 'noverify@example.com' });
    // Skip recordVerification — confirm still succeeds, issuance refuses.
    await confirmLinkRequest({ store: h.store, redis: h.redis, human, reqId: req_id });

    const r = await mint(kp, 'did:web:svc.example');
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe('verification_required');
  });

  it('refuses after the binding is revoked', async () => {
    const { kp, binding_id, human } = await setupLinked();
    await h.store.revokeBinding(binding_id, human.id);
    const r = await mint(kp, 'did:web:svc.example');
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe('binding_revoked');
  });

  it('refuses to mint for a paused human (account_paused, 403)', async () => {
    const { kp, human } = await setupLinked();
    await h.store.setHumanPaused(human.id, true);
    const r = await mint(kp, 'did:web:svc.example');
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe('account_paused');
  });

  it('resuming a paused human restores minting (reversible kill-switch)', async () => {
    const { kp, human } = await setupLinked();
    expect((await mint(kp, 'did:web:svc.example')).status).toBe(200);
    await h.store.setHumanPaused(human.id, true);
    expect((await mint(kp, 'did:web:svc.example')).status).toBe(403);
    await h.store.setHumanPaused(human.id, false);
    expect((await mint(kp, 'did:web:svc.example')).status).toBe(200);
  });

  it('a per-binding revoke survives a pause/resume cycle — resume does not re-arm a revoked agent', async () => {
    // Two agents under ONE human: A (healthy) and B (compromised).
    const a = await setupLinked({ email: 'owner@example.com' });
    const b = await setupLinked({ email: 'owner@example.com' });
    expect(b.human.id).toBe(a.human.id); // same human, two distinct bindings

    expect((await mint(a.kp, 'did:web:svc.example')).status).toBe(200);
    expect((await mint(b.kp, 'did:web:svc.example')).status).toBe(200);

    // Owner permanently revokes the compromised agent B, then uses the
    // reversible blanket kill-switch (pause -> resume) during recovery.
    await h.store.revokeBinding(b.binding_id, a.human.id);
    await h.store.setHumanPaused(a.human.id, true);
    await h.store.setHumanPaused(a.human.id, false);

    // Healthy agent A is restored by the resume...
    expect((await mint(a.kp, 'did:web:svc.example')).status).toBe(200);

    // ...but compromised agent B stays locked out: a per-binding revoke is
    // permanent and is NOT undone by resume (no silent re-arm).
    const rb = await mint(b.kp, 'did:web:svc.example');
    expect(rb.status).toBe(403);
    expect(((await rb.json()) as { error: { code: string } }).error.code).toBe('binding_revoked');
  });

  it('a paused human consumes no per-binding quota (check precedes redis.incr)', async () => {
    const { kp, binding_id, human } = await setupLinked();
    await h.store.setHumanPaused(human.id, true);
    await mint(kp, 'did:web:svc.example');
    const dayKey = `token:binding:${binding_id}:${new Date().toISOString().slice(0, 10)}`;
    expect(await h.redis.get(dayKey)).toBeNull();
  });

  it('returns binding_expired (410) — distinct from binding_revoked (403); a mint attempt does not revive it', async () => {
    const { kp, binding_id } = await setupLinked();
    // Hand-set expires_at to the past via the store.
    const bnd = await h.store.getBindingById(binding_id);
    if (!bnd) throw new Error('binding not found');
    const pastExpiry = new Date(Date.now() - 1000);
    bnd.expires_at = pastExpiry;

    const r = await mint(kp, 'did:web:svc.example');
    expect(r.status).toBe(410);
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe('binding_expired');

    // The expiry check precedes the slide (binding inactivity window): an
    // already-expired binding is NOT re-armed by a mint attempt — it
    // stays expired until the human re-links.
    const after = await h.store.getBindingById(binding_id);
    expect(after!.expires_at.getTime()).toBe(pastExpiry.getTime());
  });

  it('allows up to the raised per-binding daily limit, then throttles (429 rate_limited, not revocation)', async () => {
    const { kp, binding_id } = await setupLinked();
    const dayKey = `token:binding:${binding_id}:${new Date().toISOString().slice(0, 10)}`;
    // Preset to one below the 10,000 default so the next two mints straddle it.
    await h.redis.set(dayKey, '9999');

    expect((await mint(kp, 'did:web:svc.example')).status).toBe(200); // count → 10,000
    const throttled = await mint(kp, 'did:web:svc.example'); // count → 10,001 > 10,000
    expect(throttled.status).toBe(429);
    expect(((await throttled.json()) as { error: { code: string } }).error.code).toBe('rate_limited');
  });

  it('honours an injected per-binding daily limit (configurability)', async () => {
    const lh = await createTestHarness({ perBindingDailyTokenLimit: 1 });
    await lh.redis.flushall();
    const kp = await createAgentKeypair();
    const startResp = await postJson(lh.app, '/v1/link/start', {
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
    });
    const { req_id } = (await startResp.json()) as { req_id: string };
    const human = await lh.store.upsertHuman({ primary_email: 'limit@example.com' });
    await lh.store.recordVerification(human.id, 'email', 'magic-link');
    await confirmLinkRequest({ store: lh.store, redis: lh.redis, human, reqId: req_id });

    expect((await postMint(lh.app, kp.privateKey, kp.did, 'did:web:svc.example')).status).toBe(200);
    expect((await postMint(lh.app, kp.privateKey, kp.did, 'did:web:svc.example')).status).toBe(429);
  });

  it('scopes attestations per audience (a-token rejected by b-verifier and vice-versa)', async () => {
    const { kp } = await setupLinked();
    const b1 = (await (await mint(kp, 'did:web:a.example')).json()) as { jwt: string };
    const b2 = (await (await mint(kp, 'did:web:b.example')).json()) as { jwt: string };

    const jwks = await listPublicJwks(h.vault);
    const key = await importJWK(jwks.keys[0]!, ATTESTATION_JWT_ALG);

    await expect(
      jwtVerify(b1.jwt, key, { algorithms: [ATTESTATION_JWT_ALG], issuer: ISS, audience: 'did:web:b.example' }),
    ).rejects.toThrow();
    await expect(
      jwtVerify(b2.jwt, key, { algorithms: [ATTESTATION_JWT_ALG], issuer: ISS, audience: 'did:web:a.example' }),
    ).rejects.toThrow();
  });

  it('§10.4 — sub_h is pairwise per aud and stable across calls', async () => {
    const { kp } = await setupLinked();
    const subFor = async (aud: string) => {
      const { jwt } = (await (await mint(kp, aud)).json()) as { jwt: string };
      const jwks = await listPublicJwks(h.vault);
      const key = await importJWK(jwks.keys[0]!, ATTESTATION_JWT_ALG);
      const { payload } = await jwtVerify(jwt, key, {
        algorithms: [ATTESTATION_JWT_ALG],
        issuer: ISS,
        audience: aud,
      });
      return payload.sub_h as string;
    };

    const a1 = await subFor('did:web:a.example');
    const a2 = await subFor('did:web:a.example');
    const b1 = await subFor('did:web:b.example');

    expect(a1).toBe(a2); // stable per (binding, aud)
    expect(a1).not.toBe(b1); // pairwise across aud
  });
});
