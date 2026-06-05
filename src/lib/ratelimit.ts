import type { Context, MiddlewareHandler } from 'hono';
import type Redis from 'ioredis';
import { TrustError } from './errors.js';

export interface RateLimitOpts {
  redis: Redis;
  limit: number;
  windowSeconds: number;
  key: (c: Context) => string;
}

/**
 * Atomically-safe fixed-window counter: INCR the key, then ensure it
 * carries a TTL. EXPIRE is (re-)applied whenever the key has none — on
 * the first increment, and also if a crash/disconnect between INCR and
 * EXPIRE on an earlier request left the key without an expiry. Without
 * this, such a key would count upward forever and wedge the rate-limit /
 * quota bucket permanently. Portable across Redis versions (no
 * `EXPIRE … NX`).
 */
export async function incrFixedWindow(
  redis: Redis,
  key: string,
  windowSeconds: number,
): Promise<number> {
  const count = await redis.incr(key);
  if (count === 1 || (await redis.ttl(key)) === -1) {
    await redis.expire(key, windowSeconds);
  }
  return count;
}

export function rateLimit(opts: RateLimitOpts): MiddlewareHandler {
  return async (c, next) => {
    const k = `ratelimit:${opts.key(c)}`;
    const count = await incrFixedWindow(opts.redis, k, opts.windowSeconds);
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
    // Trust the entry `hops` from the right ONLY if the chain is at least
    // that long. A chain shorter than the configured trusted-proxy depth
    // means the request did not traverse the expected proxies, so every
    // entry is attacker-supplied — fall through to x-real-ip/unknown
    // rather than trusting the forged leftmost value (which a too-high
    // hops setting would otherwise clamp to).
    if (parts.length >= hops) {
      const pick = parts[parts.length - hops];
      if (pick) return pick;
    }
  }
  return c.req.header('x-real-ip') ?? 'unknown';
}
