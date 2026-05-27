import { z } from 'zod';

/**
 * AFAP-0006 wire shapes plus the trust.afauth.org operator API.
 *
 * The §10 attestation JWT itself is defined by AFAP-0006 §10.3.1; the
 * shapes below are for the issuance API consumed by agents and the
 * browser-facing confirm flow.
 */

// ---------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------

/**
 * Permissive DID syntax. Strict per-method validation lives elsewhere.
 * AFAP-0006 doesn't constrain DID method; v0.1 callers will mostly use
 * did:key and did:web.
 */
export const DidSchema = z
  .string()
  .min(7)
  .regex(/^did:[a-z0-9]+:.+$/i, 'must be a DID');

export const VerificationMethod = z.enum(['email', 'oauth', 'payment']);
export type VerificationMethod = z.infer<typeof VerificationMethod>;

// ---------------------------------------------------------------------
// POST /v1/link/start
// ---------------------------------------------------------------------

export const LinkStartRequest = z.object({
  agent_did: DidSchema,
  /** Public key the agent will use to sign /v1/link/poll. base64url no-pad. */
  agent_pubkey_b64: z.string().min(1),
  /** Short human-readable label shown on the confirm page. Optional. */
  agent_label: z.string().max(80).optional(),
  /** Loopback callback for desktop agents. Must be http://127.0.0.1:* */
  callback_url: z.string().url().optional(),
});
export type LinkStartRequest = z.infer<typeof LinkStartRequest>;

export const LinkStartResponse = z.object({
  req_id: z.string(),
  link_url: z.string().url(),
  poll_url: z.string().url(),
  expires_in: z.number().int().positive(),
});
export type LinkStartResponse = z.infer<typeof LinkStartResponse>;

// ---------------------------------------------------------------------
// POST /v1/link/poll
// ---------------------------------------------------------------------

export const LinkPollRequest = z.object({
  req_id: z.string(),
  /** Ed25519 signature over the UTF-8 bytes of req_id, base64url no-pad. */
  sig_b64: z.string().min(1),
});
export type LinkPollRequest = z.infer<typeof LinkPollRequest>;

export const LinkPollPendingResponse = z.object({
  state: z.literal('pending'),
});

export const LinkPollConfirmedResponse = z.object({
  state: z.literal('confirmed'),
  binding_id: z.string(),
  /** Opaque bearer token the agent stores and presents to POST /v1/token. */
  binding_token: z.string(),
  /** Unix seconds when binding_token stops being accepted. */
  binding_token_expires_at: z.number().int(),
});

export const LinkPollResponse = z.discriminatedUnion('state', [
  LinkPollPendingResponse,
  LinkPollConfirmedResponse,
]);
export type LinkPollResponse = z.infer<typeof LinkPollResponse>;

// ---------------------------------------------------------------------
// POST /v1/token
// ---------------------------------------------------------------------

export const TokenRequest = z.object({
  aud: DidSchema,
});
export type TokenRequest = z.infer<typeof TokenRequest>;

export const TokenResponse = z.object({
  jwt: z.string(),
  expires_at: z.number().int(),
  verification: VerificationMethod,
});
export type TokenResponse = z.infer<typeof TokenResponse>;

// ---------------------------------------------------------------------
// AFAP-0006 §10.3.1 — JWT claims
// ---------------------------------------------------------------------

export interface AfauthTrustClaims {
  iss: 'afauth-trust';
  aud: string; // service_did
  sub: string; // agent_did
  iat: number;
  exp: number;
  verification: VerificationMethod;
}

// ---------------------------------------------------------------------
// /link request JWT (server-signed envelope passed through the browser)
// ---------------------------------------------------------------------

/**
 * The deep-link URL embeds a JWT signed by this service's session
 * secret rather than raw query params. The browser-facing /link route
 * verifies it before rendering, which closes the spoofing window where
 * an attacker hand-crafts a ?agent=did:evil URL.
 */
export interface LinkRequestEnvelope {
  req_id: string;
  agent_did: string;
  agent_label?: string;
  iat: number;
  exp: number;
}
