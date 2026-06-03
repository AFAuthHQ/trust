import { Hono } from 'hono';
import type Redis from 'ioredis';
import { getConfig, getGoogleOauthConfig } from '../lib/config.js';
import { TrustError } from '../lib/errors.js';
import type { Store } from '../lib/store/index.js';
import { verifyLinkRequest } from '../lib/signing.js';
import { currentHuman, currentSession, OWNER_ACTION_FRESHNESS_SECONDS } from '../lib/auth.js';
import { getLogger } from '../lib/logger.js';
import { confirmLinkRequest } from '../lib/link-confirm.js';
import { layout } from '../views/layout.js';
import { landingPage } from '../views/landing.js';
import { accountPage } from '../views/account.js';
import {
  linkConfirmPage,
  linkConfirmedPage,
  linkErrorPage,
} from '../views/link.js';
import { operatorPage } from '../views/operator.js';
import { policyPage } from '../views/policy.js';

export function createPageRoutes(deps: { store: Store; redis: Redis }): Hono {
  const { store, redis } = deps;
  const app = new Hono();

  // ------ / (landing) -----------------------------------------------

  app.get('/', async (c) =>
    c.html(await layout({ title: 'trust.afauth.org', path: '/', body: landingPage() })),
  );

  // ------ /operator and /policy -------------------------------------

  app.get('/operator', async (c) =>
    c.html(
      await layout({
        title: 'Operator commitment · trust.afauth.org',
        path: '/operator',
        body: operatorPage(),
      }),
    ),
  );

  app.get('/policy', async (c) =>
    c.html(
      await layout({
        title: 'Take-down policy · trust.afauth.org',
        path: '/policy',
        body: policyPage(),
      }),
    ),
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

    // If this human previously revoked a binding for the same agent DID
    // and none is active now, confirming will mint a NEW binding for the
    // same key — warn them (esp. if it was revoked due to compromise).
    let previouslyRevokedAt: Date | null = null;
    if (human) {
      const active = await store.findActiveBindingByAgentDid(envelope.agent_did);
      if (!active) {
        const revoked = await store.findLatestRevokedBindingByAgentDid(
          envelope.agent_did,
          human.id,
        );
        previouslyRevokedAt = revoked?.revoked_at ?? null;
      }
    }

    // Mark this request as "viewed" so /v1/link/poll can advance the
    // CLI from "awaiting_signin" to "awaiting_confirm". TTL matches
    // the remaining link-request lifetime; expiring early just means
    // the CLI drops back to the more generic phase, which is fine.
    const ttlSec = Math.max(
      1,
      Math.floor((lr.expires_at.getTime() - Date.now()) / 1000),
    );
    await redis.setex(`link-viewed:${lr.id}`, ttlSec, '1');

    return c.html(
      await layout({
        title: 'Link this agent · trust.afauth.org',
        path: '/link',
        body: linkConfirmPage({
          envelope,
          rawReq: raw,
          hasSession: !!human,
          hasEmailVerification: verifications.some((v) => v.method === 'email'),
          previouslyRevokedAt,
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

    try {
      const result = await confirmLinkRequest({ store, redis, human, reqId });
      return c.html(
        await layout({
          title: 'Linked · trust.afauth.org',
          path: '/link',
          body: linkConfirmedPage({ callbackUrl: result.callback_url }),
        }),
      );
    } catch (err) {
      // Render the friendly HTML error page for known protocol errors
      // so a browser user isn't dropped on a raw JSON envelope.
      // Anything else propagates to the global JSON handler.
      if (err instanceof TrustError) {
        return c.html(
          await layout({
            title: 'Link not confirmed · trust.afauth.org',
            path: '/link',
            body: linkErrorPage({ message: err.message }),
          }),
          err.status as 400,
        );
      }
      throw err;
    }
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
        body: accountPage({
          human,
          verifications,
          bindings,
          recentTokens,
          googleEnabled: !!getGoogleOauthConfig(),
        }),
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

  // ------ POST /account/pause ---------------------------------------
  // Owner kill-switch (§8.4). Protective action — kept low-friction
  // for emergencies, so it only requires a valid session.
  app.post('/account/pause', async (c) => {
    const human = await currentHuman(c, store);
    if (!human) return c.redirect('/signin?next=%2Faccount');
    await store.setHumanPaused(human.id, true);
    getLogger().info(
      { event: 'owner.account.paused', human_id: human.id },
      'account paused by owner',
    );
    return c.redirect('/account');
  });

  // ------ POST /account/resume --------------------------------------
  // Resuming restores the account's ability to authenticate, so it
  // is an owner-binding operation subject to the §7.5 freshness floor:
  // a stale (e.g. stolen long-lived) session must re-authenticate first,
  // or it could silently undo a defensive pause. Pause stays
  // low-friction; resume does not.
  app.post('/account/resume', async (c) => {
    const session = await currentSession(c, store);
    if (!session) return c.redirect('/signin?next=%2Faccount');
    const ageMs = Date.now() - session.created_at.getTime();
    if (ageMs > OWNER_ACTION_FRESHNESS_SECONDS * 1000) {
      // Stale session — force a fresh sign-in before resuming.
      return c.redirect('/signin?next=%2Faccount');
    }
    await store.setHumanPaused(session.human_id, false);
    getLogger().info(
      { event: 'owner.account.resumed', human_id: session.human_id },
      'account resumed by owner',
    );
    return c.redirect('/account');
  });

  return app;
}
