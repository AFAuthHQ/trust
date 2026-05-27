import { Hono } from 'hono';
import type { KeyVault } from '../lib/keyvault.js';
import { listPublicJwks } from '../lib/signing.js';

export function createWellKnownRoutes(deps: { vault: KeyVault }): Hono {
  const app = new Hono();

  /**
   * AFAP-0006 §10.3.1 — JWKs document. Cached aggressively because
   * key rotation publishes new kids ≥900s before activation, and
   * consumers MUST refresh on a kid miss.
   */
  app.get('/.well-known/jwks.json', async (c) => {
    const jwks = await listPublicJwks(deps.vault);
    c.header('cache-control', 'public, max-age=300, stale-while-revalidate=900');
    return c.json(jwks);
  });

  return app;
}
