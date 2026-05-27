import { randomBytes, createHash } from 'node:crypto';

/**
 * Opaque bearer tokens for sessions, magic links, and bindings.
 *
 * Tokens are 32 random bytes, base64url-encoded (no padding). The
 * database stores only the SHA-256 hash; the raw token is shown
 * exactly once at issuance.
 */

const TOKEN_BYTES = 32;

export function generateToken(): string {
  return base64UrlEncode(randomBytes(TOKEN_BYTES));
}

export function hashToken(token: string): string {
  return createHash('sha256').update(token, 'utf8').digest('hex');
}

export function constantTimeEqualHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

function base64UrlEncode(buf: Buffer): string {
  return buf.toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}

export function base64UrlDecode(s: string): Buffer {
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  return Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}
