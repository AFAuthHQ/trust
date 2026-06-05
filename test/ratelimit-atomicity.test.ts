import { describe, expect, it } from 'vitest';
import RedisMock from 'ioredis-mock';
import type Redis from 'ioredis';
import { incrFixedWindow } from '../src/lib/ratelimit.js';

function mockRedis(): Redis {
  return new (RedisMock as unknown as new () => Redis)();
}

/**
 * Fixed-window counters MUST always carry a TTL. The old pattern
 * (`INCR` then, only when the result is 1, a separate `EXPIRE`) leaves a
 * key with NO expiry if the process dies / the connection drops in the
 * window between the two commands — the counter then climbs forever and
 * wedges that rate-limit / quota bucket permanently. incrFixedWindow
 * binds the TTL on creation AND re-arms any key that lost its expiry.
 */
describe('incrFixedWindow — fixed-window TTL binding (rate-limit atomicity)', () => {
  // NB: ioredis-mock shares one in-memory backend across instances in a
  // process, so each test uses a distinct key to stay independent.
  it('arms a TTL on the first increment', async () => {
    const r = mockRedis();
    const n = await incrFixedWindow(r, 'first', 60);
    expect(n).toBe(1);
    expect(await r.ttl('first')).toBeGreaterThan(0);
  });

  it('re-arms a key wedged without a TTL instead of letting it climb forever', async () => {
    const r = mockRedis();
    // Simulate a crash between INCR and EXPIRE on a prior request: the
    // key exists with a value but no expiry (`ttl` === -1).
    await r.set('wedged', '5');
    expect(await r.ttl('wedged')).toBe(-1);

    const n = await incrFixedWindow(r, 'wedged', 60);
    expect(n).toBe(6); // still increments the existing counter
    expect(await r.ttl('wedged')).toBeGreaterThan(0); // ...but is no longer stuck
  });

  it('keeps a positive bounded TTL across increments within the window', async () => {
    const r = mockRedis();
    await incrFixedWindow(r, 'window', 100);
    const n2 = await incrFixedWindow(r, 'window', 100);
    expect(n2).toBe(2);
    const ttl = await r.ttl('window');
    expect(ttl).toBeGreaterThan(0);
    expect(ttl).toBeLessThanOrEqual(100);
  });
});
