import { Hono } from 'hono';
import type Redis from 'ioredis';
import { z } from 'zod';
import { getConfig, getGoogleOauthConfig } from '../lib/config.js';
import { canonicalizeEmail } from '../lib/email.js';
import { TrustError } from '../lib/errors.js';
import { rateLimit, clientIp } from '../lib/ratelimit.js';
import type { Store } from '../lib/store/index.js';
import { generateToken, hashToken } from '../lib/tokens.js';
import { safeNext } from '../lib/safe-next.js';
import { sendMagicLink } from '../lib/verification/email.js';
import { clearSessionCookie, createSessionCookie, currentHuman } from '../lib/auth.js';
import { layout } from '../views/layout.js';
import {
  signinCallbackErrorPage,
  signinCallbackPage,
  signinPage,
  signinSentPage,
} from '../views/signin.js';

const MAGIC_LINK_TTL_SECONDS = 15 * 60;

const SigninRequest = z.object({
  email: z.string().email(),
  next: z.string().max(200).optional(),
});

export function createAuthRoutes(deps: { store: Store; redis: Redis }): Hono {
  const { store, redis } = deps;
  const app = new Hono();

  app.get('/signin', async (c) => {
    const next = c.req.query('next');
    const googleEnabled = !!getGoogleOauthConfig();
    // `/link?req=...` is the only entry path that needs first-time
    // signup framing. Strict prefix match — refuses other `/link*`
    // pages (none exist today, but cheap to be defensive).
    const context = next?.startsWith('/link?') ? 'link' : undefined;
    return c.html(
      await layout({
        title: 'Sign in · trust.afauth.org',
        path: '/signin',
        body: signinPage({ next, googleEnabled, context }),
      }),
    );
  });

  app.post(
    '/signin',
    rateLimit({
      redis,
      limit: 5,
      windowSeconds: 60,
      key: (c) => `signin:ip:${clientIp(c)}`,
    }),
    async (c) => {
      const form = await c.req.parseBody();
      const parsed = SigninRequest.safeParse({
        email: typeof form.email === 'string' ? form.email.trim() : '',
        next: typeof form.next === 'string' ? form.next : undefined,
      });
      if (!parsed.success) throw TrustError.invalidRequest('Email required');

      // Per-email rate limit (loose ceiling for abuse).
      const emailKey = `signin:email:${canonicalizeEmail(parsed.data.email)}`;
      const emailCount = await redis.incr(emailKey);
      if (emailCount === 1) await redis.expire(emailKey, 3600);
      if (emailCount > 10) throw TrustError.rateLimited('Too many signin attempts for this email');

      const raw = generateToken();
      const expires = new Date(Date.now() + MAGIC_LINK_TTL_SECONDS * 1000);
      await store.createMagicLink(
        parsed.data.email,
        hashToken(raw),
        expires,
        parsed.data.next,
      );

      const cfg = getConfig();
      const base = cfg.PUBLIC_BASE_URL.replace(/\/$/, '');
      const callbackUrl = `${base}/signin/callback?token=${encodeURIComponent(raw)}`;
      await sendMagicLink({ to: parsed.data.email, link: callbackUrl });

      return c.html(
        await layout({
          title: 'Check your inbox · trust.afauth.org',
          path: '/signin',
          body: signinSentPage({
            email: parsed.data.email,
            next: parsed.data.next,
          }),
        }),
      );
    },
  );

  // GET /auth/session — tiny status endpoint used by the "Check your
  // inbox" page to self-heal: it polls every few seconds and redirects
  // away once the magic-link click (in another tab) creates a session.
  // No PII in the response — just a boolean, by design. Sits under
  // /auth/* alongside /auth/google/* for namespacing.
  app.get('/auth/session', async (c) => {
    const human = await currentHuman(c, store);
    return c.json({ authenticated: !!human }, 200, {
      'cache-control': 'no-store',
    });
  });

  // GET /signin/callback — render consent page. We do NOT consume
  // the token here; pre-fetchers (M365 SafeLinks, Gmail scanner,
  // corporate egress proxies) GET email URLs to scan, and would
  // otherwise burn the link before the human ever sees it. The POST
  // handler below is the only thing that consumes the token.
  app.get('/signin/callback', async (c) => {
    const token = c.req.query('token');
    if (!token) {
      return c.html(
        await layout({
          title: 'Link unavailable · trust.afauth.org',
          path: '/signin/callback',
          body: signinCallbackErrorPage({ message: 'No sign-in token supplied.' }),
        }),
        400,
      );
    }
    const peeked = await store.peekMagicLink(hashToken(token));
    if (!peeked) {
      return c.html(
        await layout({
          title: 'Link unavailable · trust.afauth.org',
          path: '/signin/callback',
          body: signinCallbackErrorPage({
            message:
              'This sign-in link has expired or was already used. Request a new one below.',
          }),
        }),
        410,
      );
    }
    return c.html(
      await layout({
        title: 'Sign in · trust.afauth.org',
        path: '/signin/callback',
        body: signinCallbackPage({ email: peeked.email, token }),
      }),
    );
  });

  // POST /signin/callback — consumes the token atomically, sets the
  // session cookie. Same-origin: SameSite=Lax cookie + form-action
  // 'self' CSP prevent cross-site form submission.
  app.post('/signin/callback', async (c) => {
    const form = await c.req.parseBody();
    const token = typeof form.token === 'string' ? form.token : '';
    if (!token) throw TrustError.invalidRequest('Missing token');
    const consumed = await store.consumeMagicLink(hashToken(token));
    if (!consumed) throw TrustError.gone('Magic link expired or already used');

    const human = await store.upsertHuman({ primary_email: consumed.email });
    await store.recordVerification(human.id, 'email', 'magic-link');
    await createSessionCookie(c, store, human);

    // safeNext rejects absolute and protocol-relative (`//host`) values,
    // not just non-`/`-prefixed ones, so a stored `//evil.example` can't
    // become an open redirect after a legitimate sign-in.
    const next = safeNext(consumed.next_path) ?? '/account';
    return c.redirect(next);
  });

  app.post('/signout', async (c) => {
    await clearSessionCookie(c, store);
    return c.redirect('/');
  });

  return app;
}
