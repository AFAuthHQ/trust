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
 * decision.
 *
 * X-Forwarded-For is a client-APPENDED list: the leftmost entries are
 * attacker-controlled, and each trusted proxy appends the address it
 * observed on the RIGHT. We trust only the entry TRUST_TRUSTED_PROXY_HOPS
 * from the right (default 1, matching a single edge proxy such as
 * Railway/Cloudflare). Trusting the leftmost value let an attacker rotate
 * XFF to mint unlimited buckets and defeat every IP rate limit (audit #6).
 * TRUST_TRUSTED_PROXY_HOPS MUST NOT exceed the real proxy depth.
 */
export function clientIp(c: Context): string {
  const parsed = Number(process.env.TRUST_TRUSTED_PROXY_HOPS ?? '1');
  const hops = Number.isInteger(parsed) && parsed >= 1 ? parsed : 1;
  const xff = c.req.header('x-forwarded-for');
  if (xff) {
    const parts = xff.split(',').map((p) => p.trim()).filter(Boolean);
    if (parts.length > 0) {
      const idx = Math.min(parts.length - 1, Math.max(0, parts.length - hops));
      const pick = parts[idx];
      if (pick) return pick;
    }
  }
  return c.req.header('x-real-ip') ?? 'unknown';
}
