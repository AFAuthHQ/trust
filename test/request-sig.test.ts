import { describe, it, expect, beforeEach } from 'vitest';
import RedisMock from 'ioredis-mock';
import type Redis from 'ioredis';
import { verifyAgentRequestSignature, type AgentSignedRequest } from '../src/lib/request-sig.js';
import { TrustError } from '../src/lib/errors.js';

/**
 * Drift guard: pin trust's self-contained §5 verifier against the spec's
 * published reference vector. If trust's `buildCanonicalInput` ever
 * diverges from @afauthhq/core (byte-for-byte), the spec's reference
 * Ed25519 signature stops verifying and this test fails.
 *
 * Source: AFAuthHQ/spec  vectors/signatures/post-owner-invitation-email.json
 * Keypair: AFAuthHQ/spec  vectors/keypair.json  (TEST ONLY, seed 00112233…)
 */
const VECTOR = {
  did: 'did:key:z6MkiYbwC5honA2sxE7XLAyJMDFibLvVg8FgodBX4A4CaUgr',
  method: 'POST',
  targetUri: 'https://api.example.com/afauth/v1/accounts/me/owner-invitation',
  body: '{"recipient":{"type":"email","value":"alice@example.com"}}',
  contentDigest: 'sha-256=:VskmB8HOVljZMA6n/O2mWRmTgxwSFRIFGucNNkcDuao=:',
  created: 1715000100,
  expires: 1715000160,
  nonce: '2a4b6c8d0e1f3a5b',
  signatureHex:
    '479913584049dd1ef142bdc10f920648c77856ea94cf7042d30f7f982469db4ccd3846c56b81c2c02018c3776f616af18b6074dd2c29cc87f871d65449754f07',
} as const;

function hexToBase64(hex: string): string {
  return Buffer.from(hex, 'hex').toString('base64');
}

function vectorSignatureInput(
  covered = '"@method" "@target-uri" "content-digest"',
): string {
  return (
    `sig1=(${covered});created=${VECTOR.created};expires=${VECTOR.expires};` +
    `nonce="${VECTOR.nonce}";keyid="${VECTOR.did}";alg="ed25519"`
  );
}

function vectorRequest(over: Partial<AgentSignedRequest> = {}): AgentSignedRequest {
  return {
    method: VECTOR.method,
    targetUri: VECTOR.targetUri,
    signatureInput: vectorSignatureInput(),
    signature: `sig1=:${hexToBase64(VECTOR.signatureHex)}:`,
    contentDigest: VECTOR.contentDigest,
    body: new TextEncoder().encode(VECTOR.body),
    ...over,
  };
}

// now() pinned inside [created, expires] so only the property under test fails.
const insideWindow = () => VECTOR.created + 30;

describe('verifyAgentRequestSignature — spec reference vector (drift guard)', () => {
  let redis: Redis;
  beforeEach(async () => {
    // ioredis-mock shares one in-memory store across instances, so the
    // fixed vector nonce would leak between tests — flush for isolation.
    redis = new (RedisMock as unknown as new () => Redis)();
    await redis.flushall();
  });

  it('accepts the spec reference signature and returns the agent DID', async () => {
    const { keyid } = await verifyAgentRequestSignature(vectorRequest(), {
      redis,
      now: insideWindow,
    });
    expect(keyid).toBe(VECTOR.did);
  });

  it('rejects a replay of the same (keyid, nonce)', async () => {
    await verifyAgentRequestSignature(vectorRequest(), { redis, now: insideWindow });
    await expect(
      verifyAgentRequestSignature(vectorRequest(), { redis, now: insideWindow }),
    ).rejects.toMatchObject({ code: 'invalid_signature' });
  });

  it('rejects when the body is tampered (content-digest mismatch)', async () => {
    await expect(
      verifyAgentRequestSignature(
        vectorRequest({ body: new TextEncoder().encode('{"recipient":{"type":"email","value":"eve@example.com"}}') }),
        { redis, now: insideWindow },
      ),
    ).rejects.toMatchObject({ code: 'invalid_signature' });
  });

  it('rejects when @target-uri is rewritten (cross-endpoint replay)', async () => {
    await expect(
      verifyAgentRequestSignature(
        vectorRequest({ targetUri: 'https://evil.example.com/v1/token' }),
        { redis, now: insideWindow },
      ),
    ).rejects.toMatchObject({ code: 'invalid_signature' });
  });

  it('rejects a covered set missing @target-uri (§5.2 enforcement)', async () => {
    await expect(
      verifyAgentRequestSignature(
        vectorRequest({ signatureInput: vectorSignatureInput('"@method" "content-digest"') }),
        { redis, now: insideWindow },
      ),
    ).rejects.toMatchObject({ code: 'invalid_signature' });
  });

  it('rejects an expired signature (now past expires + skew)', async () => {
    await expect(
      verifyAgentRequestSignature(vectorRequest(), {
        redis,
        now: () => VECTOR.expires + 120,
      }),
    ).rejects.toMatchObject({ code: 'invalid_signature' });
  });

  it('rejects a future-dated signature (now before created - skew)', async () => {
    await expect(
      verifyAgentRequestSignature(vectorRequest(), {
        redis,
        now: () => VECTOR.created - 120,
      }),
    ).rejects.toMatchObject({ code: 'invalid_signature' });
  });

  it('rejects a missing Signature-Input header', async () => {
    await expect(
      verifyAgentRequestSignature(vectorRequest({ signatureInput: null }), {
        redis,
        now: insideWindow,
      }),
    ).rejects.toBeInstanceOf(TrustError);
  });
});
