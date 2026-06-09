/**
 * OIDC relying-party registry for "Sign in with AFAuth".
 *
 * Each client maps an OAuth `client_id` to the relying party's AFAuth
 * `service_did` and its allowed `redirect_uris`. The `service_did` is the
 * load-bearing field: it is BOTH the id_token `aud` AND the `aud` fed into
 * `deriveSubH(humanId, aud)`, so it MUST equal the value the RP advertises as
 * its service DID and that agents use as the attestation `aud`. A mismatch
 * silently breaks `sub_h` convergence (decision §3) — hence `assertOidcClients`
 * fails closed at boot on a malformed `service_did`.
 *
 * Configured via the `TRUST_OIDC_CLIENTS` env var (JSON). Example:
 *   [{"client_id":"did:web:artidrop.ai",
 *     "service_did":"did:web:artidrop.ai",
 *     "redirect_uris":["https://api.artidrop.ai/v1/auth/afauth/callback"]}]
 */

import { z } from 'zod';

export interface OidcClient {
  clientId: string;
  serviceDid: string;
  redirectUris: string[];
}

export type OidcClientRegistry = ReadonlyMap<string, OidcClient>;

const ClientSchema = z.object({
  client_id: z.string().min(1),
  service_did: z.string().min(1),
  redirect_uris: z.array(z.string().url()).min(1),
});

const DID_WEB_RE = /^did:web:[a-zA-Z0-9.\-_:%]+$/;

/**
 * Parse `TRUST_OIDC_CLIENTS` (JSON array) into a registry keyed by client_id.
 * Empty / unset → an empty registry. Throws on malformed JSON or shape.
 */
export function parseOidcClients(raw: string | undefined): OidcClientRegistry {
  const trimmed = (raw ?? '').trim();
  if (!trimmed) return new Map();
  let json: unknown;
  try {
    json = JSON.parse(trimmed);
  } catch (err) {
    throw new Error(`TRUST_OIDC_CLIENTS is not valid JSON: ${(err as Error).message}`);
  }
  const parsed = z.array(ClientSchema).safeParse(json);
  if (!parsed.success) {
    throw new Error(`TRUST_OIDC_CLIENTS shape invalid: ${parsed.error.message}`);
  }
  const map = new Map<string, OidcClient>();
  for (const c of parsed.data) {
    map.set(c.client_id, {
      clientId: c.client_id,
      serviceDid: c.service_did,
      redirectUris: c.redirect_uris,
    });
  }
  return map;
}

/**
 * Boot-time guard (decision §3): every registered client's `service_did` must
 * be a well-formed `did:web:` and every redirect_uri an absolute http(s) URL.
 * Catches the misconfiguration that would mint non-converging `sub_h` values.
 */
export function assertOidcClients(reg: OidcClientRegistry): void {
  for (const c of reg.values()) {
    if (!DID_WEB_RE.test(c.serviceDid)) {
      throw new Error(
        `OIDC client "${c.clientId}": service_did must be a did:web (got "${c.serviceDid}")`,
      );
    }
    for (const uri of c.redirectUris) {
      let u: URL;
      try {
        u = new URL(uri);
      } catch {
        throw new Error(`OIDC client "${c.clientId}": redirect_uri "${uri}" is not an absolute URL`);
      }
      if (u.protocol !== 'https:' && u.protocol !== 'http:') {
        throw new Error(`OIDC client "${c.clientId}": redirect_uri "${uri}" must be http(s)`);
      }
    }
  }
}
