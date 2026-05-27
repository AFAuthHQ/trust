import { createPublicKey, verify as cryptoVerify } from 'node:crypto';

/**
 * Verifies an Ed25519 signature over `message` using the agent's
 * public key (raw 32-byte Ed25519 key, base64url-no-pad).
 *
 * AFAP-0006 doesn't pin the agent-side algorithm. §3 of the spec
 * mandates Ed25519 for agent account keys; /v1/link/poll therefore
 * only accepts Ed25519. If a future spec broadens this, dispatch on
 * the public key's algorithm identifier.
 */
export function verifyAgentSignature(
  message: Uint8Array,
  signatureB64: string,
  publicKeyB64: string,
): boolean {
  try {
    const sig = base64UrlDecode(signatureB64);
    const rawPub = base64UrlDecode(publicKeyB64);
    if (sig.length !== 64) return false;
    if (rawPub.length !== 32) return false;

    // Node's createPublicKey wants either DER/PEM or a JWK. Build a
    // minimal JWK from the raw 32-byte Ed25519 public key.
    const key = createPublicKey({
      key: {
        kty: 'OKP',
        crv: 'Ed25519',
        x: toBase64Url(rawPub),
      },
      format: 'jwk',
    });
    return cryptoVerify(null, message, key, sig);
  } catch {
    return false;
  }
}

function base64UrlDecode(s: string): Buffer {
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}

function toBase64Url(buf: Buffer): string {
  return buf.toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
