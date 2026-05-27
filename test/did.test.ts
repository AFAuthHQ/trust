import { describe, expect, it } from 'vitest';
import {
  createAgentKeypair,
  createTestHarness,
  postJson,
  type TestHarness,
} from './helpers.js';
import { didKeyMatchesPubkey, decodeDidKey } from '../src/lib/did.js';
import { exportJWK, generateKeyPair } from 'jose';

describe('lib/did — did:key payload check', () => {
  it('round-trips a real did:key from jose-generated material', async () => {
    const { publicKey } = await generateKeyPair('EdDSA', { extractable: true });
    const jwk = await exportJWK(publicKey);
    const pub = decodeBase64Url(jwk.x!);

    // Construct the did:key the canonical way (mirrors @afauthhq/core).
    const buf = new Uint8Array(2 + 32);
    buf[0] = 0xed;
    buf[1] = 0x01;
    buf.set(pub, 2);
    const did = `did:key:z${base58btcEncode(buf)}`;

    expect(didKeyMatchesPubkey(did, jwk.x!)).toBe(true);
    expect(decodeDidKey(did)).toEqual(pub);
  });

  it('rejects when the pubkey does not match the did:key payload', async () => {
    const a = await createAgentKeypair();
    const b = await createAgentKeypair();
    // Build did:key from `a`'s pub.
    const pubA = decodeBase64Url(a.publicKeyB64);
    const buf = new Uint8Array(2 + 32);
    buf[0] = 0xed; buf[1] = 0x01;
    buf.set(pubA, 2);
    const didA = `did:key:z${base58btcEncode(buf)}`;
    // Pair it with B's pubkey — must fail.
    expect(didKeyMatchesPubkey(didA, b.publicKeyB64)).toBe(false);
  });

  it('passes through (returns true) for non-did:key methods', () => {
    expect(didKeyMatchesPubkey('did:web:agent.example', 'anything')).toBe(true);
  });

  it('returns false on malformed did:key strings', () => {
    expect(didKeyMatchesPubkey('did:key:znot-valid-base58!', 'abc')).toBe(false);
    expect(didKeyMatchesPubkey('did:key:z', 'abc')).toBe(false);
  });
});

describe('POST /v1/link/start — did:key ↔ pubkey enforcement', () => {
  it('rejects a did:key whose payload does not match the supplied pubkey', async () => {
    const h: TestHarness = await createTestHarness();
    const a = await createAgentKeypair();
    const b = await createAgentKeypair();

    const pubA = decodeBase64Url(a.publicKeyB64);
    const buf = new Uint8Array(2 + 32);
    buf[0] = 0xed; buf[1] = 0x01;
    buf.set(pubA, 2);
    const didA = `did:key:z${base58btcEncode(buf)}`;

    const r = await postJson(h.app, '/v1/link/start', {
      agent_did: didA,
      agent_pubkey_b64: b.publicKeyB64, // wrong key!
    });
    expect(r.status).toBe(400);
    const body = (await r.json()) as { error: { code: string; message: string } };
    expect(body.error.code).toBe('invalid_request');
    expect(body.error.message).toMatch(/does not match/i);
  });

  it('does not constrain did:web (out-of-band verification)', async () => {
    const h: TestHarness = await createTestHarness();
    const kp = await createAgentKeypair();
    const r = await postJson(h.app, '/v1/link/start', {
      agent_did: 'did:web:agent.example.com',
      agent_pubkey_b64: kp.publicKeyB64,
    });
    expect(r.status).toBe(200);
  });
});

function decodeBase64Url(s: string): Uint8Array {
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  return new Uint8Array(
    Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
  );
}

const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58btcEncode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]!;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = '';
  for (let i = 0; i < zeros; i++) out += BASE58_ALPHABET[0];
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58_ALPHABET[digits[i]!];
  return out;
}
