import { describe, expect, it } from 'vitest';
import { verifyAgentSignature } from '../src/lib/agent-sig.js';
import { createAgentKeypair, signEd25519 } from './helpers.js';

describe('agent-sig — Ed25519 over /v1/link/poll body', () => {
  it('accepts a correct signature', async () => {
    const { publicKeyB64, privateKey } = await createAgentKeypair();
    const message = new TextEncoder().encode('req-id-12345');
    const sig = await signEd25519(privateKey, message);
    expect(verifyAgentSignature(message, sig, publicKeyB64)).toBe(true);
  });

  it('rejects a tampered message', async () => {
    const { publicKeyB64, privateKey } = await createAgentKeypair();
    const message = new TextEncoder().encode('req-id-12345');
    const sig = await signEd25519(privateKey, message);
    const tampered = new TextEncoder().encode('req-id-12346');
    expect(verifyAgentSignature(tampered, sig, publicKeyB64)).toBe(false);
  });

  it('rejects a signature from a different key', async () => {
    const a = await createAgentKeypair();
    const b = await createAgentKeypair();
    const message = new TextEncoder().encode('req-id-12345');
    const sig = await signEd25519(a.privateKey, message);
    expect(verifyAgentSignature(message, sig, b.publicKeyB64)).toBe(false);
  });

  it('returns false (does not throw) on malformed inputs', () => {
    expect(verifyAgentSignature(new Uint8Array(), 'not-base64!', 'not-a-key')).toBe(false);
    expect(verifyAgentSignature(new Uint8Array(), '', '')).toBe(false);
    expect(verifyAgentSignature(new Uint8Array(), 'YQ', 'YQ')).toBe(false);
  });
});
