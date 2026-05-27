import { Hono } from 'hono';
import { TrustError } from '../lib/errors.js';
import type { Store } from '../lib/store/index.js';
import { currentHuman } from '../lib/auth.js';

export function createBindingRoutes(deps: { store: Store }): Hono {
  const { store } = deps;
  const app = new Hono();

  // ------ DELETE /v1/bindings/:id (human revoke) --------------------

  app.delete('/:id', async (c) => {
    const human = await currentHuman(c, store);
    if (!human) throw TrustError.unauthorized('Sign in required');

    const id = c.req.param('id');
    const revoked = await store.revokeBinding(id, human.id);
    if (!revoked) throw TrustError.notFound('Binding not found or already revoked');
    return c.json({ ok: true, revoked_at: revoked.revoked_at });
  });

  return app;
}
