import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import type Redis from 'ioredis';
import { getConfig } from './lib/config.js';
import { TrustError } from './lib/errors.js';
import { PgEncryptedKeyVault, type KeyVault } from './lib/keyvault.js';
import { getLogger } from './lib/logger.js';
import { closeRedis, getRedis } from './lib/redis.js';
import { PgStore } from './lib/store/postgres.js';
import type { Store } from './lib/store/index.js';
import { startRotationCron } from './jobs/rotation.js';
import { createAdminRoutes } from './routes/admin.js';
import { createAuthRoutes } from './routes/auth.js';
import { createBindingRoutes } from './routes/bindings.js';
import { healthRoutes } from './routes/health.js';
import { createLinkRoutes } from './routes/link.js';
import { createPageRoutes } from './routes/pages.js';
import { createTokenRoutes } from './routes/token.js';
import { createWellKnownRoutes } from './routes/wellknown.js';

export interface AppDeps {
  store: Store;
  redis: Redis;
  vault: KeyVault;
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

  app.route('/', healthRoutes);
  app.route('/', createWellKnownRoutes(deps));
  app.route('/v1/link', createLinkRoutes(deps));
  app.route('/v1/token', createTokenRoutes(deps));
  app.route('/v1/bindings', createBindingRoutes(deps));
  app.route('/admin', createAdminRoutes(deps));
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

  const app = createApp({ store, redis, vault });

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
