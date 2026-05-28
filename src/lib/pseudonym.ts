/**
 * AFAP-0006 §10.4 — pairwise human pseudonym (`sub_h`).
 *
 * For each (principal, aud) pair the attestor emits a stable,
 * opaque identifier that lets a consuming service dedupe a single
 * human's agents at its own surface, without learning who the
 * human is and without letting other services correlate the
 * same human across surfaces.
 *
 *   sub_h = base64url( HMAC-SHA256( K_pseudonym, principal_id || ":" || aud ) )
 *
 * Properties guaranteed by this construction:
 *   - Stable per (principal_id, aud).
 *   - Pairwise across distinct `aud` values.
 *   - 32-byte HMAC output → 43-char base64url, well inside the
 *     spec's [22, 86] band.
 *   - K_pseudonym is held separately from JWT signing keys and is
 *     not rotated under normal operation (§12.9).
 */
import { createHmac } from 'node:crypto';
import { getConfig } from './config.js';

/**
 * Derives `sub_h` from a principal ID (typically humans.id) and
 * the destination service's DID. Caller MUST source `keyBytes`
 * from `pseudonymKeyBytes()` in production; tests inject their
 * own 32-byte key.
 */
export function deriveSubH(
  principalId: string,
  aud: string,
  keyBytes: Buffer,
): string {
  return createHmac('sha256', keyBytes)
    .update(`${principalId}:${aud}`)
    .digest('base64url');
}

/** Decodes TRUST_PSEUDONYM_KEY_BASE64 into raw bytes. */
export function pseudonymKeyBytes(): Buffer {
  return Buffer.from(getConfig().TRUST_PSEUDONYM_KEY_BASE64, 'base64');
}
