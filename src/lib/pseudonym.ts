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
 *
 * INVARIANT (§10.4.2 stability / §10.5.1 rebinding): `sub_h` is keyed
 * on `principalId` (the durable human record id) and `aud` ONLY. It
 * MUST NOT incorporate the agent DID, the binding instance, or the
 * agent's verification key. Doing so would break stability across
 * key rotation (§8.1) and same-human rebind (§10.5.1), and would
 * reopen the per-human Sybil dedup the spec relies on (§10.5.2).
 * Same human + same service ⇒ identical `sub_h`, regardless of which
 * agent presents it or how many times that agent's key rotates.
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
