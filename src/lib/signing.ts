import {
  type JWK,
  SignJWT,
  jwtVerify,
} from 'jose';
import type { KeyVault } from './keyvault.js';
import type { AfauthTrustClaims, LinkRequestEnvelope } from './schemas.js';
import { TrustError } from './errors.js';

/**
 * AFAP-0006 §10.3.1 — JWT issuance for the afauth-trust attestor.
 *
 * The signing module no longer touches private key material directly.
 * It receives a `KeyVault` and asks for the active key's metadata
 * (kid) plus a signing key on demand. This keeps the option open to
 * swap PgEncryptedKeyVault for a KMS-backed vault without changing
 * any caller.
 *
 * AFAP-0006 mandates a 900-second max TTL for §10 JWTs and requires
 * key rotation to publish a new kid ≥900s before activation. Caller
 * code lives in routes/token.ts; this module is the crypto seam.
 *
 * The /link request envelope is unrelated to AFAP-0006 — it's a
 * server-internal HS256 JWT that wraps the parameters passed to the
 * browser via the deep link, signed with TRUST_SESSION_SECRET.
 */

export const ATTESTATION_JWT_ALG = 'EdDSA' as const;
export const MAX_ATTESTATION_TTL_SECONDS = 900;
// 30 minutes. Tight enough that an abandoned link request doesn't
// linger long, generous enough to survive an email magic-link round
// trip (deliver → notice → click → consent → bounce back) plus a
// detour to read other mail.
export const LINK_REQUEST_TTL_SECONDS = 1800;
export const ISS = 'afauth-trust';

export async function listPublicJwks(vault: KeyVault): Promise<{ keys: JWK[] }> {
  const all = await vault.list();
  const keys = all.filter((k) => k.retiredAt === null).map((k) => k.publicJwk);
  return { keys };
}

// ---------------------------------------------------------------------
// §10 attestation JWT
// ---------------------------------------------------------------------

export interface MintAttestationOpts {
  vault: KeyVault;
  agentDid: string;
  serviceDid: string;
  verification: AfauthTrustClaims['verification'];
  /** Defaults to MAX_ATTESTATION_TTL_SECONDS. Capped per AFAP-0006. */
  ttlSeconds?: number;
}

export async function mintAttestationJwt(
  opts: MintAttestationOpts,
): Promise<{ jwt: string; kid: string; iat: number; exp: number }> {
  const ttl = Math.min(
    opts.ttlSeconds ?? MAX_ATTESTATION_TTL_SECONDS,
    MAX_ATTESTATION_TTL_SECONDS,
  );
  const active = await opts.vault.getActive();
  const signingKey = await opts.vault.getSigningKey(active.kid);
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + ttl;
  const jwt = await new SignJWT({ verification: opts.verification })
    .setProtectedHeader({ alg: ATTESTATION_JWT_ALG, typ: 'JWT', kid: active.kid })
    .setIssuer(ISS)
    .setSubject(opts.agentDid)
    .setAudience(opts.serviceDid)
    .setIssuedAt(iat)
    .setExpirationTime(exp)
    .sign(signingKey);
  return { jwt, kid: active.kid, iat, exp };
}

// ---------------------------------------------------------------------
// /link request envelope (HS256, server-internal)
// ---------------------------------------------------------------------

export async function signLinkRequest(
  secret: string,
  payload: LinkRequestEnvelope,
): Promise<string> {
  const enc = new TextEncoder().encode(secret);
  return new SignJWT({
    req_id: payload.req_id,
    agent_did: payload.agent_did,
    ...(payload.agent_label ? { agent_label: payload.agent_label } : {}),
  })
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .setIssuedAt(payload.iat)
    .setExpirationTime(payload.exp)
    .sign(enc);
}

export async function verifyLinkRequest(
  secret: string,
  jwt: string,
): Promise<LinkRequestEnvelope> {
  const enc = new TextEncoder().encode(secret);
  try {
    const { payload } = await jwtVerify(jwt, enc, { algorithms: ['HS256'] });
    if (
      typeof payload.req_id !== 'string' ||
      typeof payload.agent_did !== 'string' ||
      typeof payload.iat !== 'number' ||
      typeof payload.exp !== 'number'
    ) {
      throw new Error('malformed envelope');
    }
    return {
      req_id: payload.req_id,
      agent_did: payload.agent_did,
      agent_label:
        typeof payload.agent_label === 'string' ? payload.agent_label : undefined,
      iat: payload.iat,
      exp: payload.exp,
    };
  } catch (err) {
    throw TrustError.invalidRequest(
      `Invalid link request: ${(err as Error).message}`,
    );
  }
}
