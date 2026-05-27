import type { Context, MiddlewareHandler } from 'hono';
import type Redis from 'ioredis';
import { TrustError } from './errors.js';

export interface RateLimitOpts {
  redis: Redis;
  limit: number;
  windowSeconds: number;
  key: (c: Context) => string;
}

export function rateLimit(opts: RateLimitOpts): MiddlewareHandler {
  return async (c, next) => {
    const k = `ratelimit:${opts.key(c)}`;
    const count = await opts.redis.incr(k);
    if (count === 1) {
      await opts.redis.expire(k, opts.windowSeconds);
    }
    if (count > opts.limit) {
      const ttl = await opts.redis.ttl(k);
      c.header('retry-after', String(Math.max(ttl, 0)));
      throw TrustError.rateLimited(
        `Rate limit exceeded: ${opts.limit} per ${opts.windowSeconds}s`,
      );
    }
    await next();
  };
}

/**
 * Client IP for rate-limit bucketing only — never for any authorization
 * decision. Trusts X-Forwarded-For; safe behind Railway / Cloudflare.
 */
export function clientIp(c: Context): string {
  const xff = c.req.header('x-forwarded-for');
  if (xff) {
    const first = xff.split(',')[0]?.trim();
    if (first) return first;
  }
  return c.req.header('x-real-ip') ?? 'unknown';
}
