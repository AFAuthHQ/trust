/**
 * P2 hardening: the /admin surface (key rotation/retire) is per-IP
 * rate-limited so a runaway script or brute-force attempt can't hammer
 * it unbounded. Isolated in its own file (vitest pool:forks → own
 * process/redis) so tripping the bucket doesn't affect admin.test.ts.
 */
import { describe, expect, it } from 'vitest';
import { createTestHarness } from './helpers.js';

const ADMIN = 'test-admin-secret-16';
const ADMIN_LIMIT = 30; // keep in sync with createAdminRoutes

describe('/admin rate limiting', () => {
  it(`returns 429 once the per-IP cap (${ADMIN_LIMIT}/min) is exceeded`, async () => {
    const h = await createTestHarness();
    await h.redis.flushall();
    const headers = { authorization: `Bearer ${ADMIN}` };

    let lastStatus = 0;
    for (let i = 0; i < ADMIN_LIMIT + 1; i++) {
      const r = await h.app.request('/admin/keys', { headers });
      lastStatus = r.status;
    }
    expect(lastStatus).toBe(429);
  });

  it('rate-limit applies before auth (throttles unauthenticated probing too)', async () => {
    const h = await createTestHarness();
    await h.redis.flushall();
    let lastStatus = 0;
    for (let i = 0; i < ADMIN_LIMIT + 1; i++) {
      const r = await h.app.request('/admin/keys'); // no bearer
      lastStatus = r.status;
    }
    // Once the cap is hit it's 429 rather than 401 — the limiter runs first.
    expect(lastStatus).toBe(429);
  });
});
