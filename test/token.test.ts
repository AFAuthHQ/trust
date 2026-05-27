import { describe, expect, it, beforeEach } from 'vitest';
import { importJWK, jwtVerify } from 'jose';
import {
  createAgentKeypair,
  createTestHarness,
  postJson,
  type TestHarness,
} from './helpers.js';
import { confirmLinkRequest } from '../src/lib/link-confirm.js';
import { listPublicJwks, ATTESTATION_JWT_ALG, ISS } from '../src/lib/signing.js';

describe('POST /v1/token — §10 attestation issuance', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  async function setupLinked(opts: {
    email?: string;
    verifications?: Array<{ method: 'email' | 'oauth' | 'payment'; provider: string }>;
  } = {}) {
    const kp = await createAgentKeypair();
    const startResp = await postJson(h.app, '/v1/link/start', {
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
    });
    const { req_id } = (await startResp.json()) as { req_id: string };

    const human = await h.store.upsertHuman({
      primary_email: opts.email ?? 'alice@example.com',
    });
    for (const v of opts.verifications ?? [{ method: 'email', provider: 'magic-link' }]) {
      await h.store.recordVerification(human.id, v.method, v.provider);
    }
    const confirmed = await confirmLinkRequest({
      store: h.store,
      redis: h.redis,
      human,
      reqId: req_id,
    });
    return {
      kp,
      human,
      agentDid: kp.did,
      binding_id: confirmed.binding_id,
      binding_token: confirmed.binding_token,
    };
  }

  it('requires a bearer binding token', async () => {
    const r = await postJson(h.app, '/v1/token', { aud: 'did:web:svc.example' });
    expect(r.status).toBe(401);
  });

  it('rejects an unknown binding token', async () => {
    const r = await postJson(
      h.app,
      '/v1/token',
      { aud: 'did:web:svc.example' },
      { headers: { authorization: 'Bearer not-a-real-token' } },
    );
    expect(r.status).toBe(401);
  });

  it('issues a JWT that verifies offline against the JWKS', async () => {
    const { binding_token, binding_id, agentDid } = await setupLinked();
    const r = await postJson(
      h.app,
      '/v1/token',
      { aud: 'did:web:svc.example' },
      { headers: { authorization: `Bearer ${binding_token}` } },
    );
    expect(r.status).toBe(200);
    const body = (await r.json()) as {
      jwt: string;
      expires_at: number;
      verification: string;
    };
    expect(body.verification).toBe('email');

    // Offline verify with the JWKS, mirroring what a consuming service does.
    const jwks = await listPublicJwks(h.vault);
    const key = await importJWK(jwks.keys[0]!, ATTESTATION_JWT_ALG);
    const { payload } = await jwtVerify(body.jwt, key, {
      algorithms: [ATTESTATION_JWT_ALG],
      issuer: ISS,
      audience: 'did:web:svc.example',
    });
    expect(payload.sub).toBe(agentDid);
    expect(payload.verification).toBe('email');

    // The binding's last_used_at was bumped.
    const refreshed = await h.store.getBindingById(binding_id);
    expect(refreshed?.last_used_at).toBeTruthy();
  });

  it('emits the strongest verification (payment > oauth > email)', async () => {
    const { binding_token } = await setupLinked({
      verifications: [
        { method: 'email', provider: 'magic-link' },
        { method: 'oauth', provider: 'github' },
        { method: 'payment', provider: 'stripe' },
      ],
    });
    const r = await postJson(
      h.app,
      '/v1/token',
      { aud: 'did:web:svc.example' },
      { headers: { authorization: `Bearer ${binding_token}` } },
    );
    const body = (await r.json()) as { verification: string };
    expect(body.verification).toBe('payment');
  });

  it('falls back to email when stronger methods are absent', async () => {
    const { binding_token } = await setupLinked({
      verifications: [{ method: 'email', provider: 'magic-link' }],
    });
    const r = await postJson(
      h.app,
      '/v1/token',
      { aud: 'did:web:svc.example' },
      { headers: { authorization: `Bearer ${binding_token}` } },
    );
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
    // Skip recordVerification — should still be able to confirm, but token issuance refuses.
    const confirmed = await confirmLinkRequest({
      store: h.store,
      redis: h.redis,
      human,
      reqId: req_id,
    });

    const r = await postJson(
      h.app,
      '/v1/token',
      { aud: 'did:web:svc.example' },
      { headers: { authorization: `Bearer ${confirmed.binding_token}` } },
    );
    expect(r.status).toBe(403);
    const body = (await r.json()) as { error: { code: string } };
    expect(body.error.code).toBe('verification_required');
  });

  it('refuses after the binding is revoked', async () => {
    const { binding_token, binding_id, human } = await setupLinked();
    await h.store.revokeBinding(binding_id, human.id);
    const r = await postJson(
      h.app,
      '/v1/token',
      { aud: 'did:web:svc.example' },
      { headers: { authorization: `Bearer ${binding_token}` } },
    );
    expect(r.status).toBe(403);
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe(
      'binding_revoked',
    );
  });

  it('returns binding_expired (410) — distinct from binding_revoked (403)', async () => {
    const { binding_token, binding_id } = await setupLinked();
    // Hand-set expires_at to the past via the store.
    const b = await h.store.getBindingById(binding_id);
    if (!b) throw new Error('binding not found');
    b.expires_at = new Date(Date.now() - 1000);

    const r = await postJson(
      h.app,
      '/v1/token',
      { aud: 'did:web:svc.example' },
      { headers: { authorization: `Bearer ${binding_token}` } },
    );
    expect(r.status).toBe(410);
    expect(((await r.json()) as { error: { code: string } }).error.code).toBe(
      'binding_expired',
    );
  });

  it('different requests for different audiences are scoped per audience', async () => {
    const { binding_token } = await setupLinked();
    const r1 = await postJson(
      h.app,
      '/v1/token',
      { aud: 'did:web:a.example' },
      { headers: { authorization: `Bearer ${binding_token}` } },
    );
    const r2 = await postJson(
      h.app,
      '/v1/token',
      { aud: 'did:web:b.example' },
      { headers: { authorization: `Bearer ${binding_token}` } },
    );
    const b1 = (await r1.json()) as { jwt: string };
    const b2 = (await r2.json()) as { jwt: string };

    const jwks = await listPublicJwks(h.vault);
    const key = await importJWK(jwks.keys[0]!, ATTESTATION_JWT_ALG);

    // A JWT minted for a.example MUST be rejected by b.example verifier.
    await expect(
      jwtVerify(b1.jwt, key, {
        algorithms: [ATTESTATION_JWT_ALG],
        issuer: ISS,
        audience: 'did:web:b.example',
      }),
    ).rejects.toThrow();

    // And vice-versa.
    await expect(
      jwtVerify(b2.jwt, key, {
        algorithms: [ATTESTATION_JWT_ALG],
        issuer: ISS,
        audience: 'did:web:a.example',
      }),
    ).rejects.toThrow();
  });
});
