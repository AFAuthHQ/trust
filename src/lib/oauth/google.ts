import { randomBytes, createHash } from 'node:crypto';
import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTVerifyGetKey } from 'jose';
import { canonicalizeEmail } from '../email.js';

/**
 * Google OAuth 2.0 + OpenID Connect helpers for trust.afauth.org.
 *
 * We use the auth-code-with-PKCE flow purely as a one-shot verification
 * channel — no refresh tokens stored, no Google API calls beyond the
 * ID-token exchange. The ID token alone gives us {sub, email,
 * email_verified}, which is everything the trust attestor needs.
 *
 * The module exports a `dependencies` factory so tests can inject a
 * fake fetcher + JWKS rather than hitting Google.
 */

const GOOGLE_ISSUER = 'https://accounts.google.com';
const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';

export interface GoogleOauthConfig {
  clientId: string;
  clientSecret: string;
  redirectUri: string;
}

export interface GoogleIdentity {
  /** Stable per-Google-account identifier. The thing to key off. */
  subject: string;
  email: string;
  emailVerified: boolean;
}

export interface GoogleOauthDeps {
  /** Defaults to global fetch; tests override. */
  fetch?: typeof fetch;
  /**
   * Key resolver passed to jwtVerify. Production uses
   * createRemoteJWKSet against Google's certs URL; tests pass a
   * createLocalJWKSet so the suite can verify tokens it minted itself
   * without hitting the network.
   */
  jwks?: JWTVerifyGetKey;
  /**
   * Override the accepted issuer (tests). Production accepts both
   * Google-spec issuer forms (with and without scheme).
   */
  issuer?: string | string[];
}

export class GoogleOauthClient {
  private readonly cfg: GoogleOauthConfig;
  private readonly deps: Required<GoogleOauthDeps>;

  constructor(cfg: GoogleOauthConfig, deps: GoogleOauthDeps = {}) {
    this.cfg = cfg;
    this.deps = {
      fetch: deps.fetch ?? fetch,
      jwks: deps.jwks ?? createRemoteJWKSet(new URL(GOOGLE_JWKS_URL)),
      issuer: deps.issuer ?? [GOOGLE_ISSUER, 'accounts.google.com'],
    };
  }

  /**
   * Build the redirect URL the browser should go to. Caller is
   * responsible for stashing `state` + `codeVerifier` server-side
   * (keyed by `state`) so the callback can validate them.
   */
  authorizationUrl(opts: { state: string; nonce: string; codeChallenge: string }): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: this.cfg.clientId,
      redirect_uri: this.cfg.redirectUri,
      scope: 'openid email profile',
      access_type: 'online',
      prompt: 'select_account',
      state: opts.state,
      nonce: opts.nonce,
      code_challenge: opts.codeChallenge,
      code_challenge_method: 'S256',
    });
    return `${GOOGLE_AUTH_URL}?${params.toString()}`;
  }

  /**
   * Exchange the authorization code for an ID token, then verify the
   * ID token against Google's JWKS. Returns the identity claims we
   * care about. Throws on any verification failure.
   */
  async exchangeCode(opts: {
    code: string;
    codeVerifier: string;
    expectedNonce: string;
  }): Promise<GoogleIdentity> {
    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: opts.code,
      client_id: this.cfg.clientId,
      client_secret: this.cfg.clientSecret,
      redirect_uri: this.cfg.redirectUri,
      code_verifier: opts.codeVerifier,
    });

    const r = await this.deps.fetch(GOOGLE_TOKEN_URL, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    if (!r.ok) {
      const text = await r.text().catch(() => '');
      throw new Error(`Google token endpoint returned ${r.status}: ${text.slice(0, 200)}`);
    }
    const payload = (await r.json()) as { id_token?: string };
    if (!payload.id_token) {
      throw new Error('Google token response missing id_token');
    }

    const { payload: claims } = await jwtVerify(payload.id_token, this.deps.jwks, {
      issuer: this.deps.issuer,
      audience: this.cfg.clientId,
    });
    assertNonce(claims, opts.expectedNonce);

    const subject = typeof claims.sub === 'string' ? claims.sub : '';
    const email = typeof claims.email === 'string' ? canonicalizeEmail(claims.email) : '';
    const emailVerified = claims.email_verified === true;
    if (!subject) throw new Error('Google ID token missing sub');
    if (!email) throw new Error('Google ID token missing email');
    return { subject, email, emailVerified };
  }
}

function assertNonce(claims: JWTPayload, expected: string): void {
  const got = typeof claims.nonce === 'string' ? claims.nonce : '';
  if (got !== expected) {
    throw new Error('Google ID token nonce mismatch');
  }
}

// ---- PKCE + state helpers (pure, easily unit-testable) -------------

export function generateState(): string {
  return b64url(randomBytes(32));
}

export function generateNonce(): string {
  return b64url(randomBytes(16));
}

export function generateCodeVerifier(): string {
  // RFC 7636 §4.1: 43–128 chars, base64url(32 bytes) = 43 chars.
  return b64url(randomBytes(32));
}

export function codeChallengeFor(verifier: string): string {
  return b64url(createHash('sha256').update(verifier).digest());
}

function b64url(buf: Buffer): string {
  return buf.toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
