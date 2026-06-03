import { Hono } from 'hono';
import type Redis from 'ioredis';
import { getConfig } from '../lib/config.js';
import { TrustError } from '../lib/errors.js';
import { rateLimit, clientIp } from '../lib/ratelimit.js';
import {
  LinkPollRequest,
  LinkStartRequest,
  type LinkStartResponse,
} from '../lib/schemas.js';
import {
  LINK_REQUEST_TTL_SECONDS,
  signLinkRequest,
} from '../lib/signing.js';
import type { Store } from '../lib/store/index.js';
import { verifyAgentSignature } from '../lib/agent-sig.js';
import { currentHuman } from '../lib/auth.js';
import { didKeyMatchesPubkey } from '../lib/did.js';
import { confirmLinkRequest } from '../lib/link-confirm.js';

export function createLinkRoutes(deps: { store: Store; redis: Redis }): Hono {
  const { store, redis } = deps;
  const app = new Hono();

  // ------ POST /v1/link/start (agent → deep link) -------------------

  app.post(
    '/start',
    rateLimit({
      redis,
      limit: 30,
      windowSeconds: 60,
      key: (c) => `link-start:ip:${clientIp(c)}`,
    }),
    async (c) => {
      const body = LinkStartRequest.safeParse(await c.req.json().catch(() => ({})));
      if (!body.success) {
        throw TrustError.invalidRequest(
          `Invalid /v1/link/start body: ${body.error.message}`,
        );
      }

      // Anti-substitution: if agent_did is a did:key, its payload MUST
      // match agent_pubkey_b64. Otherwise a malicious caller could
      // submit someone else's DID alongside its own keypair, then
      // present a deep link that misleads the human about which agent
      // they're authorising. did:web and other methods can't be
      // checked in-band (would require a network fetch) — skipped.
      if (!didKeyMatchesPubkey(body.data.agent_did, body.data.agent_pubkey_b64)) {
        throw TrustError.invalidRequest(
          'agent_did did:key payload does not match agent_pubkey_b64',
        );
      }

      // Per-agent_did cap, prevents agent-side abuse / flood.
      const perAgentKey = `link-start:agent:${body.data.agent_did}`;
      const perAgentCount = await redis.incr(perAgentKey);
      if (perAgentCount === 1) await redis.expire(perAgentKey, 3600);
      if (perAgentCount > 20) throw TrustError.rateLimited('Too many link requests for this agent');

      // Loopback callback safety: only 127.0.0.1 / localhost allowed.
      if (body.data.callback_url) {
        const u = new URL(body.data.callback_url);
        if (!(u.hostname === '127.0.0.1' || u.hostname === 'localhost')) {
          throw TrustError.invalidRequest('callback_url must be loopback');
        }
      }

      const expiresAt = new Date(Date.now() + LINK_REQUEST_TTL_SECONDS * 1000);
      const lr = await store.createLinkRequest({
        agent_did: body.data.agent_did,
        agent_label: body.data.agent_label,
        agent_pubkey_b64: body.data.agent_pubkey_b64,
        expires_at: expiresAt,
        callback_url: body.data.callback_url,
      });

      const cfg = getConfig();
      const reqJwt = await signLinkRequest(cfg.TRUST_SESSION_SECRET, {
        req_id: lr.id,
        agent_did: lr.agent_did,
        agent_label: lr.agent_label ?? undefined,
        iat: Math.floor(lr.created_at.getTime() / 1000),
        exp: Math.floor(expiresAt.getTime() / 1000),
      });

      const base = cfg.PUBLIC_BASE_URL.replace(/\/$/, '');
      const resp: LinkStartResponse = {
        req_id: lr.id,
        link_url: `${base}/link?req=${encodeURIComponent(reqJwt)}`,
        poll_url: `${base}/v1/link/poll`,
        expires_in: LINK_REQUEST_TTL_SECONDS,
      };
      return c.json(resp);
    },
  );

  // ------ POST /v1/link/confirm (browser → mark bound) --------------

  app.post('/confirm', async (c) => {
    const human = await currentHuman(c, store);
    if (!human) throw TrustError.unauthorized('Sign in required to confirm a link');

    const body = await c.req.json().catch(() => ({}));
    const reqId = typeof body?.req_id === 'string' ? body.req_id : null;
    if (!reqId) throw TrustError.invalidRequest('req_id required');

    const result = await confirmLinkRequest({ store, redis, human, reqId });
    return c.json({
      ok: true,
      binding_id: result.binding_id,
      callback_url: result.callback_url,
    });
  });

  // ------ POST /v1/link/confirm-e2e (test-mode only) ---------------
  //
  // Gated behind TRUST_E2E_AUTOCONFIRM=1. 404s in any deployment
  // where the flag is unset. See `src/lib/config.ts` for the
  // rationale; see `spec/harness/e2e/` for the consumer.

  app.post('/confirm-e2e', async (c) => {
    const cfg = getConfig();
    if (!cfg.TRUST_E2E_AUTOCONFIRM) {
      return c.json(
        { error: { code: 'not_found', message: 'Not found' } },
        404,
      );
    }

    const body = await c.req.json().catch(() => ({}));
    const reqId = typeof body?.req_id === 'string' ? body.req_id : null;
    const email = typeof body?.email === 'string' ? body.email : null;
    if (!reqId || !email) {
      throw TrustError.invalidRequest('req_id and email required');
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      throw TrustError.invalidRequest('email must be a well-formed address');
    }

    const human = await store.upsertHuman({ primary_email: email });
    // Mark the human verified so they can later receive an
    // afauth-trust attestation. In the real flow this happens via
    // magic-link or OAuth; in test mode we assert it directly.
    await store.recordVerification(human.id, 'email', 'e2e-autoconfirm');

    const result = await confirmLinkRequest({ store, redis, human, reqId });
    return c.json({
      ok: true,
      binding_id: result.binding_id,
      callback_url: result.callback_url,
    });
  });

  // ------ POST /v1/link/poll (agent → binding id + expiry) ---------

  app.post(
    '/poll',
    rateLimit({
      redis,
      limit: 60,
      windowSeconds: 60,
      key: (c) => `link-poll:ip:${clientIp(c)}`,
    }),
    async (c) => {
      const body = LinkPollRequest.safeParse(await c.req.json().catch(() => ({})));
      if (!body.success) {
        throw TrustError.invalidRequest(
          `Invalid /v1/link/poll body: ${body.error.message}`,
        );
      }

      const lr = await store.getLinkRequest(body.data.req_id);
      if (!lr) throw TrustError.notFound('Link request not found');

      // Agent proves it controls the same keypair it sent in /v1/link/start.
      const ok = verifyAgentSignature(
        new TextEncoder().encode(lr.id),
        body.data.sig_b64,
        lr.agent_pubkey_b64,
      );
      if (!ok) throw TrustError.invalidSignature();

      if (lr.state === 'pending') {
        // `phase` lets the agent show a tighter waiting message
        // ("Waiting for you to sign in…" vs "Waiting for you to
        // confirm…"). Derived from the per-request viewed marker that
        // /link sets on first browser render.
        const viewed = await redis.exists(`link-viewed:${lr.id}`);
        return c.json({
          state: 'pending' as const,
          phase: viewed ? ('awaiting_confirm' as const) : ('awaiting_signin' as const),
        });
      }
      if (lr.state !== 'confirmed') {
        throw TrustError.linkRequestExpired(`Link request is ${lr.state}`);
      }

      // Pop the binding info from Redis exactly once.
      const cached = await redis.getdel(`binding-token:${lr.id}`);
      if (!cached) {
        throw TrustError.linkRequestExpired(
          'Binding already retrieved or expired',
        );
      }
      const payload = JSON.parse(cached);
      return c.json({ state: 'confirmed' as const, ...payload });
    },
  );

  return app;
}
