import { describe, expect, it, beforeEach } from 'vitest';
import { importJWK, jwtVerify } from 'jose';
import { setTestEnv } from './helpers.js';
import { MemoryStore } from '../src/lib/store/memory.js';
import { PgEncryptedKeyVault } from '../src/lib/keyvault.js';
import {
  ATTESTATION_JWT_ALG,
  ISS,
  MAX_ATTESTATION_TTL_SECONDS,
  listPublicJwks,
  mintAttestationJwt,
} from '../src/lib/signing.js';

function makeVault() {
  const store = new MemoryStore();
  const kek = Buffer.alloc(32, 0xab);
  return { store, vault: new PgEncryptedKeyVault(store, kek) };
}

describe('signing — JWT shape per AFAP-0006 §10.3.1', () => {
  beforeEach(() => setTestEnv());

  it('bootstraps a first signing key on empty store', async () => {
    const { vault } = makeVault();
    const k1 = await vault.ensureActiveKey();
    expect(k1.kid).toBeTruthy();
    expect(k1.alg).toBe(ATTESTATION_JWT_ALG);
    expect(k1.publicJwk.kty).toBe('OKP');
    expect(k1.publicJwk.crv).toBe('Ed25519');

    // Second call reuses, doesn't insert a duplicate.
    const k2 = await vault.ensureActiveKey();
    expect(k2.kid).toBe(k1.kid);
  });

  it('mints a JWT with the spec-pinned shape', async () => {
    const { vault } = makeVault();
    await vault.ensureActiveKey();
    const { jwt, iat, exp } = await mintAttestationJwt({
      vault,
      agentDid: 'did:key:z6MkAgent',
      serviceDid: 'did:web:service.example',
      verification: 'email',
    });

    const [headerB64] = jwt.split('.');
    expect(headerB64).toBeTruthy();
    const header = JSON.parse(Buffer.from(headerB64!, 'base64url').toString());
    expect(header.alg).toBe(ATTESTATION_JWT_ALG);
    expect(header.typ).toBe('JWT');
    expect(typeof header.kid).toBe('string');

    expect(exp - iat).toBeLessThanOrEqual(MAX_ATTESTATION_TTL_SECONDS);
    expect(exp - iat).toBeGreaterThan(0);
  });

  it('caps ttl at 900s even when a larger ttl is requested', async () => {
    const { vault } = makeVault();
    await vault.ensureActiveKey();
    const { iat, exp } = await mintAttestationJwt({
      vault,
      agentDid: 'did:key:z6MkAgent',
      serviceDid: 'did:web:service.example',
      verification: 'email',
      ttlSeconds: 9999,
    });
    expect(exp - iat).toBe(MAX_ATTESTATION_TTL_SECONDS);
  });

  it('JWKS roundtrip: a minted JWT verifies against the published JWKS', async () => {
    const { vault } = makeVault();
    await vault.ensureActiveKey();
    const { jwt } = await mintAttestationJwt({
      vault,
      agentDid: 'did:key:z6MkAgent',
      serviceDid: 'did:web:service.example',
      verification: 'oauth',
    });

    const jwks = await listPublicJwks(vault);
    expect(jwks.keys.length).toBe(1);

    const key = jwks.keys[0]!;
    const publicKey = await importJWK(key, ATTESTATION_JWT_ALG);

    const { payload, protectedHeader } = await jwtVerify(jwt, publicKey, {
      algorithms: [ATTESTATION_JWT_ALG],
      issuer: ISS,
      audience: 'did:web:service.example',
    });

    expect(protectedHeader.kid).toBe(key.kid);
    expect(payload.iss).toBe(ISS);
    expect(payload.sub).toBe('did:key:z6MkAgent');
    expect(payload.aud).toBe('did:web:service.example');
    expect(payload.verification).toBe('oauth');
    expect(typeof payload.iat).toBe('number');
    expect(typeof payload.exp).toBe('number');

    // Per AFAP-0006: no PII fields permitted.
    expect(payload.email).toBeUndefined();
    expect(payload.phone).toBeUndefined();
    expect(payload.name).toBeUndefined();
  });
});

describe('PgEncryptedKeyVault — at-rest encryption', () => {
  beforeEach(() => setTestEnv());

  it('persists ciphertext, not cleartext', async () => {
    const { store, vault } = makeVault();
    const meta = await vault.rotate();
    const rows = await store.listActiveSigningKeys();
    const row = rows.find((r) => r.kid === meta.kid)!;
    expect(row.privateJwkEnc.length).toBeGreaterThan(0);
    expect(row.privateJwkIv.length).toBe(12); // GCM IV
    // The ciphertext must not contain the JWK's plaintext key marker.
    const raw = row.privateJwkEnc.toString('utf8');
    expect(raw).not.toContain('"d"');
    expect(raw).not.toContain('Ed25519');
  });

  it('rejects KEKs of the wrong length', () => {
    const store = new MemoryStore();
    expect(() => new PgEncryptedKeyVault(store, new Uint8Array(16))).toThrow(/32 bytes/);
  });

  it('decrypts and signs with the same KEK across calls', async () => {
    const { vault } = makeVault();
    const k = await vault.rotate();
    const r1 = await mintAttestationJwt({
      vault,
      agentDid: 'did:key:z6MkA',
      serviceDid: 'did:web:s.example',
      verification: 'email',
    });
    const r2 = await mintAttestationJwt({
      vault,
      agentDid: 'did:key:z6MkB',
      serviceDid: 'did:web:s.example',
      verification: 'email',
    });
    expect(r1.kid).toBe(k.kid);
    expect(r2.kid).toBe(k.kid);
    // Different subjects produce different JWTs even within one second.
    expect(r1.jwt).not.toBe(r2.jwt);
  });

  it('cannot decrypt with a different KEK (auth tag check)', async () => {
    const { store, vault } = makeVault();
    await vault.rotate();

    const wrongKek = Buffer.alloc(32, 0xcd);
    const wrongVault = new PgEncryptedKeyVault(store, wrongKek);
    await expect(
      mintAttestationJwt({
        vault: wrongVault,
        agentDid: 'did:key:z6MkA',
        serviceDid: 'did:web:s.example',
        verification: 'email',
      }),
    ).rejects.toThrow();
  });
});
