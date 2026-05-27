/**
 * Minimal did:key decoding for /v1/link/start's "does this agent
 * actually control the keypair it claims?" check.
 *
 * Only handles ed25519-pub (multicodec 0xed 0x01), which is what
 * §3 of core.md mandates for agent account keys. did:web isn't
 * decoded here — verifying did:web requires fetching a DID document,
 * which we leave to consuming services that opt into stricter
 * binding checks.
 */

import { TrustError } from './errors.js';

const ED25519_PUB_VARINT = [0xed, 0x01] as const;
const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * Decodes did:key:z<base58btc(ed25519-multicodec || pubkey)> to the
 * raw 32-byte Ed25519 public key.
 *
 * Throws TrustError.invalidRequest on any malformed input — never
 * crashes.
 */
export function decodeDidKey(did: string): Uint8Array {
  if (!did.startsWith('did:key:z')) {
    throw TrustError.invalidRequest(`not a did:key:z... value: ${did}`);
  }
  const decoded = base58btcDecode(did.slice('did:key:z'.length));
  if (decoded.length < 2) {
    throw TrustError.invalidRequest('did:key payload too short');
  }
  if (decoded[0] !== ED25519_PUB_VARINT[0] || decoded[1] !== ED25519_PUB_VARINT[1]) {
    throw TrustError.invalidRequest(
      `unsupported did:key multicodec prefix: ed25519-pub (0xed01) required`,
    );
  }
  const pub = decoded.slice(2);
  if (pub.length !== 32) {
    throw TrustError.invalidRequest(
      `did:key Ed25519 public key must be 32 bytes, got ${pub.length}`,
    );
  }
  return pub;
}

/**
 * Returns true iff agent_did is a did:key whose payload matches the
 * supplied 32-byte public key (base64url no-pad).
 *
 * For other DID methods (did:web, etc.) — returns true without
 * checking. Verifying those requires a network fetch and is out of
 * scope for the in-band /v1/link/start anti-spoofing pass.
 */
export function didKeyMatchesPubkey(agentDid: string, pubkeyB64: string): boolean {
  if (!agentDid.startsWith('did:key:z')) return true;
  let didBytes: Uint8Array;
  try {
    didBytes = decodeDidKey(agentDid);
  } catch {
    return false;
  }
  const pubBytes = base64UrlDecode(pubkeyB64);
  if (didBytes.length !== pubBytes.length) return false;
  // Constant-time compare to keep error timing flat.
  let diff = 0;
  for (let i = 0; i < didBytes.length; i++) {
    diff |= (didBytes[i] ?? 0) ^ (pubBytes[i] ?? 0);
  }
  return diff === 0;
}

function base64UrlDecode(s: string): Uint8Array {
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  return new Uint8Array(
    Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
  );
}

function base58btcDecode(s: string): Uint8Array {
  if (s.length === 0) return new Uint8Array();
  const map = new Int8Array(128).fill(-1);
  for (let i = 0; i < BASE58_ALPHABET.length; i++) {
    map[BASE58_ALPHABET.charCodeAt(i)] = i;
  }
  // Count '1' (alphabet[0]) prefix — each one is a leading zero byte.
  let leadingZeros = 0;
  while (leadingZeros < s.length && s[leadingZeros] === BASE58_ALPHABET[0]) {
    leadingZeros++;
  }

  // Build the big-endian byte representation as a little-endian array,
  // then reverse. Each base58 character contributes one digit; we
  // multiply the running total by 58 and add the digit.
  const bytes: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (code > 127 || map[code]! < 0) {
      throw TrustError.invalidRequest(`invalid base58 character: ${s[i]}`);
    }
    let carry = map[code]!;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  // bytes is little-endian; reverse into the output and prepend
  // explicit leading zero bytes from the '1' prefix.
  const out = new Uint8Array(leadingZeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[leadingZeros + i] = bytes[bytes.length - 1 - i]!;
  }
  return out;
}
