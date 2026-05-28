import { Hono, type Context } from 'hono';
import type Redis from 'ioredis';
import { currentHuman, createSessionCookie } from '../lib/auth.js';
import { getGoogleOauthConfig } from '../lib/config.js';
import { getLogger } from '../lib/logger.js';
import {
  GoogleOauthClient,
  type GoogleOauthDeps,
  codeChallengeFor,
  generateCodeVerifier,
  generateNonce,
  generateState,
} from '../lib/oauth/google.js';
import { rateLimit, clientIp } from '../lib/ratelimit.js';
import type { Store } from '../lib/store/index.js';
import { layout } from '../views/layout.js';
import { signinCallbackErrorPage } from '../views/signin.js';

const STATE_TTL_SECONDS = 5 * 60;
const PROVIDER = 'google';

interface PendingState {
  codeVerifier: string;
  nonce: string;
  next?: string;
  /** session_id when the start call came from a logged-in human. */
  linkingHumanId?: string;
}

export interface OauthGoogleDeps {
  store: Store;
  redis: Redis;
  /** Optional GoogleOauthClient deps (fetch/jwks/issuer overrides for tests). */
  google?: GoogleOauthDeps;
}

/**
 * Routes for "Continue with Google" sign-in / sign-up / link.
 *
 * The single callback handles five outcomes:
 *  A — sign-in:    no session, sub already known      → log in as known human
 *  B — link:       session, sub unknown               → record verification on session human
 *  C — sign-up:    no session, sub unknown            → create human + session
 *  D — hijack:     session, sub known to other human  → 409
 *  E — idempotent: session, sub known to same human   → refresh + redirect
 */
export function createOauthGoogleRoutes(deps: OauthGoogleDeps): Hono {
  const { store, redis } = deps;
  const app = new Hono();

  app.get(
    '/start',
    rateLimit({
      redis,
      limit: 20,
      windowSeconds: 60,
      key: (c) => `oauth-google-start:ip:${clientIp(c)}`,
    }),
    async (c) => {
      const cfg = getGoogleOauthConfig();
      if (!cfg) return notConfiguredPage(c);

      const next = c.req.query('next');
      const session = await currentHuman(c, store);

      const state = generateState();
      const nonce = generateNonce();
      const codeVerifier = generateCodeVerifier();
      const codeChallenge = codeChallengeFor(codeVerifier);

      const pending: PendingState = {
        codeVerifier,
        nonce,
        ...(safeNext(next) ? { next: safeNext(next)! } : {}),
        ...(session ? { linkingHumanId: session.id } : {}),
      };
      await redis.set(
        stateKey(state),
        JSON.stringify(pending),
        'EX',
        STATE_TTL_SECONDS,
      );

      const client = new GoogleOauthClient(cfg, deps.google);
      const url = client.authorizationUrl({ state, nonce, codeChallenge });
      return c.redirect(url, 302);
    },
  );

  app.get(
    '/callback',
    rateLimit({
      redis,
      limit: 30,
      windowSeconds: 60,
      key: (c) => `oauth-google-callback:ip:${clientIp(c)}`,
    }),
    async (c) => {
      const cfg = getGoogleOauthConfig();
      if (!cfg) return notConfiguredPage(c);

      // Google sends back ?error=access_denied when the user cancels.
      const upstreamErr = c.req.query('error');
      if (upstreamErr) {
        return errorPage(c, 'Google sign-in was cancelled.', 400);
      }

      const code = c.req.query('code');
      const state = c.req.query('state');
      if (!code || !state) {
        return errorPage(c, 'Missing authorization code or state.', 400);
      }

      const raw = await redis.get(stateKey(state));
      if (!raw) {
        return errorPage(
          c,
          'This sign-in attempt expired or was already used. Start over below.',
          400,
        );
      }
      // One-shot: delete before exchange so a duplicate callback can't
      // re-use it. Lost in-flight failures are recoverable by clicking
      // the button again.
      await redis.del(stateKey(state));

      const pending = JSON.parse(raw) as PendingState;

      const client = new GoogleOauthClient(cfg, deps.google);
      let identity;
      try {
        identity = await client.exchangeCode({
          code,
          codeVerifier: pending.codeVerifier,
          expectedNonce: pending.nonce,
        });
      } catch (err) {
        getLogger().warn({ err }, 'google id_token exchange failed');
        return errorPage(
          c,
          'Could not verify your Google identity. Try again.',
          400,
        );
      }

      if (!identity.emailVerified) {
        return errorPage(
          c,
          'Your Google account email is not verified by Google. Sign in with a different method.',
          400,
        );
      }

      const existing = await store.findVerificationByExternalSubject(
        PROVIDER,
        identity.subject,
      );
      const sessionHumanId = pending.linkingHumanId
        ? (await store.getHumanById(pending.linkingHumanId))?.id ?? null
        : null;

      // Case D — hijack: this Google account is linked to a *different*
      // human than the one currently signed in.
      if (existing && sessionHumanId && existing.human_id !== sessionHumanId) {
        return errorPage(
          c,
          'This Google account is already linked to a different trust.afauth.org account. Sign out of that account first.',
          409,
        );
      }

      // Case E — already linked to this session: refresh verified_at,
      // redirect. recordVerification handles the upsert.
      if (existing && sessionHumanId && existing.human_id === sessionHumanId) {
        await store.recordVerification(
          sessionHumanId,
          'oauth',
          PROVIDER,
          identity.subject,
        );
        return c.redirect(pickNext(pending.next, '/account'));
      }

      // Case A — sign-in: not linking-context, Google sub already known.
      if (existing && !sessionHumanId) {
        const human = await store.getHumanById(existing.human_id);
        if (!human) {
          // Verification orphaned (human deleted) — treat as fresh signup.
          return signUpFlow(c, store, identity, pending.next);
        }
        await store.recordVerification(human.id, 'oauth', PROVIDER, identity.subject);
        await createSessionCookie(c, store, human);
        return c.redirect(pickNext(pending.next, '/account'));
      }

      // Case B — link: logged-in human is adding a new Google identity.
      if (sessionHumanId) {
        const human = await store.getHumanById(sessionHumanId);
        if (!human) {
          // Session-human disappeared mid-flow; bail to sign-in.
          return errorPage(c, 'Your session expired. Sign in again.', 401);
        }
        if (human.primary_email !== identity.email) {
          return errorPage(
            c,
            `Your Google account email (${identity.email}) doesn't match the email on this trust.afauth.org account. Sign in to Google with the right account, or change your Google account from the picker.`,
            400,
          );
        }
        try {
          await store.recordVerification(human.id, 'oauth', PROVIDER, identity.subject);
        } catch (err) {
          // Partial-index uniqueness violation — the sub is taken.
          // This is technically the hijack case for stores that don't
          // pre-check, but we already pre-checked via existing above.
          // Surface a clear message anyway.
          getLogger().warn({ err }, 'recordVerification conflict on link');
          return errorPage(
            c,
            'Could not link this Google account; it may already be in use.',
            409,
          );
        }
        return c.redirect(pickNext(pending.next, '/account'));
      }

      // Case C — sign-up: brand-new identity, no current session.
      return signUpFlow(c, store, identity, pending.next);
    },
  );

  // POST /auth/google/revoke — disconnect Google from the signed-in
  // account. Kept on the same /auth/google base for cohesion; the
  // /account page POSTs here.
  app.post(
    '/revoke',
    rateLimit({
      redis,
      limit: 20,
      windowSeconds: 60,
      key: (c) => `oauth-google-revoke:ip:${clientIp(c)}`,
    }),
    async (c) => {
      const human = await currentHuman(c, store);
      if (!human) return c.redirect('/signin?next=%2Faccount');
      await store.revokeVerification(human.id, 'oauth', PROVIDER);
      return c.redirect('/account');
    },
  );

  return app;
}

// ---- helpers --------------------------------------------------------

async function signUpFlow(
  c: Context,
  store: Store,
  identity: { subject: string; email: string },
  next: string | undefined,
): Promise<Response> {
  const human = await store.upsertHuman({ primary_email: identity.email });
  await store.recordVerification(human.id, 'oauth', PROVIDER, identity.subject);
  // Google has proven control of this email. If the human has no
  // existing email verification on file, record one so token issuance
  // has a fallback `verification: 'email'` claim when oauth is later
  // revoked. Skip if they already have ANY email verification — adding
  // a redundant row would just clutter the account view (the picker
  // only cares about method, not provider).
  const existing = await store.listVerifications(human.id);
  if (!existing.some((v) => v.method === 'email')) {
    await store.recordVerification(human.id, 'email', 'google-verified');
  }
  await createSessionCookie(c, store, human);
  return c.redirect(pickNext(next, '/account'));
}

function errorPage(
  c: Context,
  message: string,
  status: number,
): Promise<Response> | Response {
  return c.html(
    layout({
      title: 'Sign in unavailable · trust.afauth.org',
      path: '/auth/google/callback',
      body: signinCallbackErrorPage({ message }),
    }),
    status as 400,
  );
}

/**
 * Shown when GOOGLE_OAUTH_CLIENT_ID/SECRET aren't set. The UI hides
 * the button in this case, but defend against direct URL hits with a
 * clean HTML page rather than a JSON 404 envelope.
 */
function notConfiguredPage(c: Context): Promise<Response> | Response {
  return errorPage(c, 'Google sign-in is not enabled on this server.', 404);
}

function stateKey(state: string): string {
  return `oauth:google:state:${state}`;
}

/** Only allow same-site relative paths; absolute URLs would be open-redirect. */
function safeNext(next: string | undefined): string | undefined {
  if (!next) return undefined;
  if (!next.startsWith('/') || next.startsWith('//')) return undefined;
  if (next.length > 200) return undefined;
  return next;
}

function pickNext(next: string | undefined, fallback: string): string {
  return safeNext(next) ?? fallback;
}
