import { Hono } from 'hono';
import type Redis from 'ioredis';
import { getConfig } from '../lib/config.js';
import { TrustError } from '../lib/errors.js';
import type { Store } from '../lib/store/index.js';
import { verifyLinkRequest } from '../lib/signing.js';
import { currentHuman } from '../lib/auth.js';
import { confirmLinkRequest } from '../lib/link-confirm.js';
import { layout } from '../views/layout.js';
import { landingPage } from '../views/landing.js';
import { accountPage } from '../views/account.js';
import {
  linkConfirmPage,
  linkConfirmedPage,
  linkErrorPage,
} from '../views/link.js';

export function createPageRoutes(deps: { store: Store; redis: Redis }): Hono {
  const { store, redis } = deps;
  const app = new Hono();

  // ------ / (landing) -----------------------------------------------

  app.get('/', async (c) =>
    c.html(await layout({ title: 'trust.afauth.org', path: '/', body: landingPage() })),
  );

  // ------ /link (deep-link confirm) ---------------------------------

  app.get('/link', async (c) => {
    const raw = c.req.query('req');
    if (!raw) {
      return c.html(
        await layout({
          title: 'Link request missing · trust.afauth.org',
          path: '/link',
          body: linkErrorPage({ message: 'No link request was supplied.' }),
        }),
      );
    }

    let envelope;
    try {
      envelope = await verifyLinkRequest(getConfig().TRUST_SESSION_SECRET, raw);
    } catch {
      return c.html(
        await layout({
          title: 'Invalid link · trust.afauth.org',
          path: '/link',
          body: linkErrorPage({
            message: 'This link is invalid or has expired. Ask your agent to start a new link request.',
          }),
        }),
      );
    }

    const lr = await store.getLinkRequest(envelope.req_id);
    if (!lr || lr.state !== 'pending' || lr.expires_at.getTime() < Date.now()) {
      return c.html(
        await layout({
          title: 'Link unavailable · trust.afauth.org',
          path: '/link',
          body: linkErrorPage({
            message:
              !lr || lr.expires_at.getTime() < Date.now()
                ? 'This link has expired.'
                : `This link is already ${lr.state}.`,
          }),
        }),
      );
    }

    const human = await currentHuman(c, store);
    const verifications = human ? await store.listVerifications(human.id) : [];
    return c.html(
      await layout({
        title: 'Link this agent · trust.afauth.org',
        path: '/link',
        body: linkConfirmPage({
          envelope,
          rawReq: raw,
          hasSession: !!human,
          hasEmailVerification: verifications.some((v) => v.method === 'email'),
        }),
      }),
    );
  });

  // ------ POST /link/confirm (form submit from /link page) ----------

  app.post('/link/confirm', async (c) => {
    const human = await currentHuman(c, store);
    if (!human) throw TrustError.unauthorized('Sign in required to confirm a link');

    const form = await c.req.parseBody();
    const reqId = typeof form.req_id === 'string' ? form.req_id : null;
    if (!reqId) throw TrustError.invalidRequest('req_id required');

    const result = await confirmLinkRequest({ store, redis, human, reqId });

    return c.html(
      await layout({
        title: 'Linked · trust.afauth.org',
        path: '/link',
        body: linkConfirmedPage({ callbackUrl: result.callback_url }),
      }),
    );
  });

  // ------ /account --------------------------------------------------

  app.get('/account', async (c) => {
    const human = await currentHuman(c, store);
    if (!human) return c.redirect('/signin?next=%2Faccount');

    const [verifications, bindings, recentTokens] = await Promise.all([
      store.listVerifications(human.id),
      store.listBindingsByHuman(human.id),
      store.recentTokensByHuman(human.id, 20),
    ]);

    return c.html(
      await layout({
        title: 'Account · trust.afauth.org',
        path: '/account',
        body: accountPage({ human, verifications, bindings, recentTokens }),
      }),
    );
  });

  // ------ POST /account/bindings/:id/revoke -------------------------

  app.post('/account/bindings/:id/revoke', async (c) => {
    const human = await currentHuman(c, store);
    if (!human) return c.redirect('/signin?next=%2Faccount');
    const id = c.req.param('id');
    await store.revokeBinding(id, human.id);
    return c.redirect('/account');
  });

  return app;
}
