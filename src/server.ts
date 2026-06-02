import { serve } from '@hono/node-server';
import { serveStatic } from '@hono/node-server/serve-static';
import { Hono } from 'hono';
import type Redis from 'ioredis';
import { getConfig } from './lib/config.js';
import { TrustError } from './lib/errors.js';
import { PgEncryptedKeyVault, type KeyVault } from './lib/keyvault.js';
import { getLogger } from './lib/logger.js';
import type { GoogleOauthDeps } from './lib/oauth/google.js';
import { closeRedis, getRedis } from './lib/redis.js';
import { PgStore } from './lib/store/postgres.js';
import type { Store } from './lib/store/index.js';
import { startRotationCron } from './jobs/rotation.js';
import { createAdminRoutes } from './routes/admin.js';
import { createAuthRoutes } from './routes/auth.js';
import { createBindingRoutes } from './routes/bindings.js';
import { healthRoutes } from './routes/health.js';
import { createLinkRoutes } from './routes/link.js';
import { createOauthGoogleRoutes } from './routes/oauth-google.js';
import { createPageRoutes } from './routes/pages.js';
import { createTokenRoutes } from './routes/token.js';
import { createWellKnownRoutes } from './routes/wellknown.js';

export interface AppDeps {
  store: Store;
  redis: Redis;
  vault: KeyVault;
  /** §10.7 per-binding daily attestation mint cap. Defaults to DEFAULT_PER_BINDING_DAILY_TOKEN_LIMIT. */
  perBindingDailyTokenLimit?: number;
  /** Test-only: inject a fake fetcher / JWKS for the Google OAuth client. */
  googleOauthDeps?: GoogleOauthDeps;
}

export function createApp(deps: AppDeps): Hono {
  const app = new Hono();

  app.use('*', async (c, next) => {
    const start = Date.now();
    await next();
    const ms = Date.now() - start;
    if (process.env.NODE_ENV !== 'test') {
      getLogger().info(
        {
          method: c.req.method,
          path: new URL(c.req.url).pathname,
          status: c.res.status,
          ms,
        },
        'request',
      );
    }
  });

  // Security response headers. Applied to every response, including
  // /v1/* JSON APIs — HSTS and X-Content-Type-Options are universally
  // applicable; CSP is HTML-meaningful but doesn't hurt JSON.
  //
  // CSP allows 'unsafe-inline' for styles because views/layout.ts
  // injects an inline <style> block (hash-based CSP is a possible
  // future tightening if we extract the stylesheet to its own file).
  // img-src allows the favicon hosted at https://afauth.org/favicon.svg.
  app.use('*', async (c, next) => {
    await next();
    c.header(
      'strict-transport-security',
      'max-age=63072000; includeSubDomains; preload',
    );
    c.header('x-content-type-options', 'nosniff');
    c.header('x-frame-options', 'DENY');
    c.header('referrer-policy', 'strict-origin-when-cross-origin');
    c.header(
      'permissions-policy',
      'camera=(), microphone=(), geolocation=(), payment=()',
    );
    c.header(
      'content-security-policy',
      [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
      ].join('; '),
    );
  });

  app.onError((err, c) => {
    if (err instanceof TrustError) {
      return c.json(err.toEnvelope(), { status: err.status as 400 });
    }
    getLogger().error({ err }, 'unhandled error');
    return c.json(
      { error: { code: 'internal_error', message: 'Internal server error' } },
      500,
    );
  });

  app.notFound((c) =>
    c.json({ error: { code: 'not_found', message: 'Not found' } }, 404),
  );

  // Static assets out of trust/public — favicon + any future public
  // bytes that should be served same-origin so the page is fully
  // self-contained (and so CSP can stay tight: img-src 'self' data:).
  app.use('/favicon.svg', serveStatic({ path: './public/favicon.svg' }));
  app.use('/inbox-poll.js', serveStatic({ path: './public/inbox-poll.js' }));
  app.use('/link-callback.js', serveStatic({ path: './public/link-callback.js' }));
  app.use('/account-confirm.js', serveStatic({ path: './public/account-confirm.js' }));

  app.route('/', healthRoutes);
  app.route('/', createWellKnownRoutes(deps));
  app.route('/v1/link', createLinkRoutes(deps));
  app.route('/v1/token', createTokenRoutes(deps));
  app.route('/v1/bindings', createBindingRoutes(deps));
  app.route('/admin', createAdminRoutes(deps));
  app.route(
    '/auth/google',
    createOauthGoogleRoutes({ store: deps.store, redis: deps.redis, google: deps.googleOauthDeps }),
  );
  app.route('/', createAuthRoutes(deps));
  app.route('/', createPageRoutes(deps));

  return app;
}

async function main(): Promise<void> {
  const cfg = getConfig();
  const log = getLogger();

  const store = new PgStore();
  await store.init();
  log.info('postgres connected, schema applied');

  const redis = getRedis();
  await redis.ping();
  log.info('redis connected');

  const kek = Buffer.from(cfg.TRUST_KEK_BASE64, 'base64');
  const vault = new PgEncryptedKeyVault(store, kek);
  const key = await vault.ensureActiveKey();
  log.info({ kid: key.kid, alg: key.alg }, 'signing key ready (encrypted at rest)');

  const app = createApp({
    store,
    redis,
    vault,
    perBindingDailyTokenLimit: cfg.TRUST_PER_BINDING_DAILY_TOKEN_LIMIT,
  });

  const rotationCron = startRotationCron(vault, cfg.TRUST_ROTATION_SCHEDULE);
  if (rotationCron) {
    log.info({ schedule: cfg.TRUST_ROTATION_SCHEDULE }, 'rotation cron scheduled');
  } else {
    log.info('rotation cron disabled (TRUST_ROTATION_SCHEDULE empty)');
  }

  const server = serve(
    { fetch: app.fetch, port: cfg.PORT },
    (info) => {
      log.info(
        { port: info.port, env: cfg.NODE_ENV, base: cfg.PUBLIC_BASE_URL },
        'trust.afauth.org listening',
      );
    },
  );

  const shutdown = async (signal: string) => {
    log.info({ signal }, 'shutting down');
    if (rotationCron) rotationCron.stop();
    server.close();
    try {
      await store.close();
    } catch (err) {
      log.error({ err }, 'error closing postgres');
    }
    try {
      await closeRedis();
    } catch (err) {
      log.error({ err }, 'error closing redis');
    }
    process.exit(0);
  };

  process.on('SIGTERM', () => void shutdown('SIGTERM'));
  process.on('SIGINT', () => void shutdown('SIGINT'));
}

const isEntry = import.meta.url === `file://${process.argv[1]}`;
if (isEntry) {
  main().catch((err) => {
    console.error('Failed to start server:', err);
    process.exit(1);
  });
}
