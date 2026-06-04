import { Hono } from 'hono';
import type Redis from 'ioredis';
import { z } from 'zod';
import { getConfig } from '../lib/config.js';
import { TrustError } from '../lib/errors.js';
import type { KeyVault } from '../lib/keyvault.js';
import { getLogger } from '../lib/logger.js';
import { rateLimit, clientIp } from '../lib/ratelimit.js';
import { MAX_ATTESTATION_TTL_SECONDS } from '../lib/signing.js';
import { constantTimeEqual } from '../lib/tokens.js';

/** Per-IP cap on the admin surface (key rotation/retire). */
const ADMIN_RATE_LIMIT = 30;

/**
 * Admin routes — bearer-auth'd by TRUST_ADMIN_SECRET. Intended to be
 * called manually or by a control-plane script, not the public.
 *
 * /admin/keys/rotate    — mint a new signing kid, by default scheduled
 *                         to activate in 900s so JWKS consumers have
 *                         time to refresh (per AFAP-0006).
 *
 * /admin/keys/retire    — remove a kid from /.well-known/jwks.json
 *                         once you're confident no in-flight tokens
 *                         still need it.
 */

const RotateBody = z.object({
  /**
   * Seconds in the future the new key becomes eligible for signing.
   * Defaults to MAX_ATTESTATION_TTL_SECONDS (900), which matches the
   * AFAP-0006 cache-drain guarantee. Set to 0 only when you know the
   * JWKS has been pre-cached at every consumer (rare).
   */
  delaySeconds: z.number().int().min(0).max(86_400).optional(),
});

const RetireBody = z.object({
  kid: z.string().min(1),
});

export function createAdminRoutes(deps: { vault: KeyVault; redis: Redis }): Hono {
  const { vault, redis } = deps;
  const app = new Hono();

  // Throttle the admin surface per IP — runs BEFORE auth so brute-force
  // / runaway-script probing is bounded regardless of the bearer.
  app.use(
    '*',
    rateLimit({
      redis,
      limit: ADMIN_RATE_LIMIT,
      windowSeconds: 60,
      key: (c) => `admin:ip:${clientIp(c)}`,
    }),
  );

  app.use('*', async (c, next) => {
    const cfg = getConfig();
    const ip = clientIp(c);
    const path = new URL(c.req.url).pathname;
    const auth = c.req.header('authorization') ?? '';
    const m = auth.match(/^Bearer\s+(.+)$/i);
    // Constant-time compare so the admin secret can't be recovered via a
    // timing side-channel on this internet-reachable endpoint (audit #7).
    if (!m || !constantTimeEqual(m[1]!, cfg.TRUST_ADMIN_SECRET)) {
      // Audit trail: every privileged-surface auth failure is logged.
      getLogger().warn(
        { event: 'admin.auth_failed', ip, method: c.req.method, path },
        'admin auth failed',
      );
      throw TrustError.unauthorized('admin bearer required');
    }
    // Audit trail: log every authorized admin action (rotations/retires
    // are the highest-impact operations in the service).
    getLogger().warn(
      { event: 'admin.request', ip, method: c.req.method, path },
      'admin request authorized',
    );
    await next();
  });

  app.post('/keys/rotate', async (c) => {
    const parsed = RotateBody.safeParse(await c.req.json().catch(() => ({})));
    if (!parsed.success) {
      throw TrustError.invalidRequest(`bad body: ${parsed.error.message}`);
    }
    const delay = parsed.data.delaySeconds ?? MAX_ATTESTATION_TTL_SECONDS;
    const activeFrom = new Date(Date.now() + delay * 1000);
    const meta = await vault.rotate({ activeFrom });
    return c.json({
      ok: true,
      kid: meta.kid,
      alg: meta.alg,
      active_from: meta.activeFrom.toISOString(),
      delay_seconds: delay,
    });
  });

  app.post('/keys/retire', async (c) => {
    const parsed = RetireBody.safeParse(await c.req.json().catch(() => ({})));
    if (!parsed.success) {
      throw TrustError.invalidRequest(`bad body: ${parsed.error.message}`);
    }
    await vault.retire(parsed.data.kid);
    return c.json({ ok: true, retired_kid: parsed.data.kid });
  });

  app.get('/keys', async (c) => {
    const keys = await vault.list();
    const now = Date.now();
    return c.json({
      keys: keys.map((k) => ({
        kid: k.kid,
        alg: k.alg,
        active_from: k.activeFrom.toISOString(),
        active: k.retiredAt === null && k.activeFrom.getTime() <= now,
        retired: k.retiredAt !== null,
      })),
    });
  });

  return app;
}
