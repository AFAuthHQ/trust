/**
 * "Sign in with AFAuth" — minimal OIDC provider (authorization-code + PKCE).
 *
 * trust already authenticates humans (email magic-link + Google) and already
 * derives the pairwise `sub_h`. This exposes that as an OIDC issuer so a relying
 * party (artidrop today) can land a human in the SAME account their attested
 * agent created: the id_token's `sub` IS the `sub_h`, under the same issuer the
 * attestation carries (after the M3 unification).
 *
 * Scope (MVP): one response_type (`code`), PKCE S256 required, a sub-only
 * id_token (no email — the privacy property), auto-consent (RPs are first-party).
 * The token endpoint takes JSON (server-to-server; sidesteps the global CSRF
 * guard, which only acts on form/text bodies).
 */

import type { Context } from 'hono';
import { Hono } from 'hono';
import type Redis from 'ioredis';
import { createHash } from 'node:crypto';
import { currentHuman } from '../lib/auth.js';
import { getConfig } from '../lib/config.js';
import type { KeyVault } from '../lib/keyvault.js';
import type { OidcClient, OidcClientRegistry } from '../lib/oidc-clients.js';
import { deriveSubH, pseudonymKeyBytes } from '../lib/pseudonym.js';
import { mintIdToken } from '../lib/signing.js';
import type { Store } from '../lib/store/index.js';
import { generateToken } from '../lib/tokens.js';

/** Stashed /authorize params survive the signin bounce (keeps `next` short). */
const AUTH_REQUEST_TTL_SECONDS = 600;
/** Authorization code lifetime — short and single-use. */
const CODE_TTL_SECONDS = 120;

interface AuthRequest {
  clientId: string;
  redirectUri: string;
  state?: string;
  codeChallenge: string;
  nonce?: string;
  scope: string;
}

interface CodeRecord {
  humanId: string;
  clientId: string;
  serviceDid: string;
  redirectUri: string;
  codeChallenge: string;
  nonce?: string;
}

function issuer(): string {
  return getConfig().PUBLIC_BASE_URL.replace(/\/$/, '');
}

function s256(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

/** Set query params on a URI, preserving any it already carries. */
function withParams(uri: string, params: Record<string, string | undefined>): string {
  const u = new URL(uri);
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined) u.searchParams.set(k, v);
  }
  return u.toString();
}

/** A pre-redirect error (bad client/redirect_uri) — never bounce to an
 *  unvalidated target, so render plainly instead. */
function authError(c: Context, error: string, description: string): Response {
  return c.text(`${error}: ${description}`, 400);
}

async function readTokenParams(c: Context): Promise<Record<string, string>> {
  const ct = c.req.header('content-type') ?? '';
  if (ct.includes('application/json')) {
    try {
      const j = (await c.req.json()) as Record<string, unknown>;
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(j ?? {})) if (typeof v === 'string') out[k] = v;
      return out;
    } catch {
      return {};
    }
  }
  try {
    const f = await c.req.parseBody();
    const out: Record<string, string> = {};
    for (const [k, v] of Object.entries(f)) if (typeof v === 'string') out[k] = v;
    return out;
  } catch {
    return {};
  }
}

export function createOidcRoutes(deps: {
  store: Store;
  redis: Redis;
  vault: KeyVault;
  oidcClients: OidcClientRegistry;
}): Hono {
  const { store, redis, vault, oidcClients } = deps;
  const app = new Hono();

  // ---- discovery ----------------------------------------------------
  app.get('/.well-known/openid-configuration', (c) => {
    const iss = issuer();
    c.header('cache-control', 'public, max-age=300');
    return c.json({
      issuer: iss,
      authorization_endpoint: `${iss}/oidc/authorize`,
      token_endpoint: `${iss}/oidc/token`,
      jwks_uri: getConfig().JWKS_PUBLIC_URL,
      scopes_supported: ['openid'],
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      subject_types_supported: ['pairwise'],
      id_token_signing_alg_values_supported: ['EdDSA'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      claims_supported: ['iss', 'sub', 'aud', 'exp', 'iat', 'nonce'],
    });
  });

  // ---- authorization endpoint --------------------------------------
  app.get('/oidc/authorize', async (c) => {
    const rid = c.req.query('rid');
    let req: AuthRequest;
    let client: OidcClient | undefined;

    if (rid) {
      // Resume after a signin bounce.
      const raw = await redis.get(`oidc:areq:${rid}`);
      if (!raw) return authError(c, 'invalid_request', 'authorization request expired — please try again');
      req = JSON.parse(raw) as AuthRequest;
      client = oidcClients.get(req.clientId);
      if (!client) return authError(c, 'invalid_client', 'unknown client_id');
    } else {
      const clientId = c.req.query('client_id') ?? '';
      const redirectUri = c.req.query('redirect_uri') ?? '';
      client = oidcClients.get(clientId);
      // Validate client + redirect_uri BEFORE trusting the redirect target.
      if (!client) return authError(c, 'invalid_client', 'unknown client_id');
      if (!client.redirectUris.includes(redirectUri)) {
        return authError(c, 'invalid_request', 'redirect_uri is not registered for this client');
      }
      const responseType = c.req.query('response_type') ?? '';
      const codeChallenge = c.req.query('code_challenge') ?? '';
      const method = c.req.query('code_challenge_method') ?? '';
      const scope = c.req.query('scope') ?? '';
      const state = c.req.query('state') ?? undefined;
      const nonce = c.req.query('nonce') ?? undefined;
      // redirect_uri is validated now → param errors may bounce back to it.
      if (responseType !== 'code') {
        return c.redirect(withParams(redirectUri, { error: 'unsupported_response_type', state }));
      }
      if (!codeChallenge || method !== 'S256') {
        return c.redirect(
          withParams(redirectUri, { error: 'invalid_request', error_description: 'PKCE S256 required', state }),
        );
      }
      if (!scope.split(/\s+/).includes('openid')) {
        return c.redirect(
          withParams(redirectUri, { error: 'invalid_scope', error_description: 'openid scope required', state }),
        );
      }
      req = { clientId, redirectUri, state, codeChallenge, nonce, scope };
    }

    const human = await currentHuman(c, store);
    if (!human) {
      // Stash the validated request, bounce through the existing signin flow.
      const newRid = rid ?? generateToken();
      if (!rid) {
        await redis.set(`oidc:areq:${newRid}`, JSON.stringify(req), 'EX', AUTH_REQUEST_TTL_SECONDS);
      }
      return c.redirect(`/signin?next=${encodeURIComponent(`/oidc/authorize?rid=${newRid}`)}`);
    }

    // Signed in → issue a single-use authorization code bound to PKCE + RP.
    const code = generateToken();
    const record: CodeRecord = {
      humanId: human.id,
      clientId: req.clientId,
      serviceDid: client.serviceDid,
      redirectUri: req.redirectUri,
      codeChallenge: req.codeChallenge,
      nonce: req.nonce,
    };
    await redis.set(`oidc:code:${code}`, JSON.stringify(record), 'EX', CODE_TTL_SECONDS);
    if (rid) await redis.del(`oidc:areq:${rid}`);
    return c.redirect(withParams(req.redirectUri, { code, state: req.state }));
  });

  // ---- token endpoint (server-to-server; JSON) ---------------------
  app.post('/oidc/token', async (c) => {
    const params = await readTokenParams(c);
    if (params.grant_type !== 'authorization_code') {
      return c.json({ error: 'unsupported_grant_type' }, 400);
    }
    const { code, code_verifier: verifier, client_id: clientId, redirect_uri: redirectUri } = params;
    if (!code || !verifier || !clientId || !redirectUri) {
      return c.json(
        { error: 'invalid_request', error_description: 'missing code/code_verifier/client_id/redirect_uri' },
        400,
      );
    }

    // Single-use: read then delete the code regardless of outcome.
    const key = `oidc:code:${code}`;
    const raw = await redis.get(key);
    await redis.del(key);
    if (!raw) return c.json({ error: 'invalid_grant', error_description: 'unknown or expired code' }, 400);
    const rec = JSON.parse(raw) as CodeRecord;

    if (rec.clientId !== clientId) {
      return c.json({ error: 'invalid_grant', error_description: 'client mismatch' }, 400);
    }
    if (rec.redirectUri !== redirectUri) {
      return c.json({ error: 'invalid_grant', error_description: 'redirect_uri mismatch' }, 400);
    }
    if (s256(verifier) !== rec.codeChallenge) {
      return c.json({ error: 'invalid_grant', error_description: 'PKCE verification failed' }, 400);
    }

    // sub_h is keyed on the human + the RP's service DID — identical to the
    // value the attestation stamped at signup, so the human converges onto the
    // agent-created account.
    const subH = deriveSubH(rec.humanId, rec.serviceDid, pseudonymKeyBytes());
    const { jwt, exp, iat } = await mintIdToken({
      vault,
      issuer: issuer(),
      subH,
      audience: rec.serviceDid,
      nonce: rec.nonce,
    });
    c.header('cache-control', 'no-store');
    return c.json({ id_token: jwt, token_type: 'Bearer', expires_in: exp - iat });
  });

  return app;
}
