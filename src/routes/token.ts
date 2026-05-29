import { Hono } from 'hono';
import type Redis from 'ioredis';
import { TrustError } from '../lib/errors.js';
import type { KeyVault } from '../lib/keyvault.js';
import { rateLimit, clientIp } from '../lib/ratelimit.js';
import { deriveSubH, pseudonymKeyBytes } from '../lib/pseudonym.js';
import { TokenRequest, type TokenResponse, type VerificationMethod } from '../lib/schemas.js';
import { mintAttestationJwt } from '../lib/signing.js';
import type { Store } from '../lib/store/index.js';
import { hashToken } from '../lib/tokens.js';

const PER_BINDING_DAILY_LIMIT = 1000;

/**
 * Ranks verification methods strongest → weakest. The trust attestor
 * always emits the strongest method the linked human has on file at
 * issuance time — the consuming service decides whether that meets
 * its threshold.
 */
const VERIFICATION_RANK: VerificationMethod[] = ['payment', 'oauth', 'email'];

export function createTokenRoutes(deps: { store: Store; redis: Redis; vault: KeyVault }): Hono {
  const { store, redis, vault } = deps;
  const app = new Hono();

  // ------ POST /v1/token --------------------------------------------

  app.post(
    '/',
    rateLimit({
      redis,
      limit: 60,
      windowSeconds: 60,
      key: (c) => `token:ip:${clientIp(c)}`,
    }),
    async (c) => {
      const auth = c.req.header('authorization') ?? '';
      const m = auth.match(/^Bearer\s+(.+)$/i);
      if (!m) throw TrustError.unauthorized('Bearer binding token required');
      const bindingToken = m[1]!;

      const body = TokenRequest.safeParse(await c.req.json().catch(() => ({})));
      if (!body.success) {
        throw TrustError.invalidRequest(`Invalid /v1/token body: ${body.error.message}`);
      }

      const binding = await store.getBindingByTokenHash(hashToken(bindingToken));
      if (!binding) throw TrustError.unauthorized('Unknown binding token');
      if (binding.revoked_at) throw TrustError.bindingRevoked();
      if (binding.expires_at.getTime() < Date.now()) {
        throw TrustError.bindingExpired();
      }

      // Per-binding daily quota.
      const dayKey = `token:binding:${binding.id}:${new Date().toISOString().slice(0, 10)}`;
      const dayCount = await redis.incr(dayKey);
      if (dayCount === 1) await redis.expire(dayKey, 86400);
      if (dayCount > PER_BINDING_DAILY_LIMIT) {
        throw TrustError.rateLimited(
          `Per-binding daily limit (${PER_BINDING_DAILY_LIMIT}) exceeded`,
        );
      }

      const verifications = await store.listVerifications(binding.human_id);
      if (verifications.length === 0) {
        throw TrustError.verificationRequired(
          'Human has no active verification methods; visit /account to add one',
        );
      }

      const verification = strongestVerification(verifications.map((v) => v.method));
      if (!verification) {
        throw TrustError.internal('Failed to rank verifications');
      }

      // sub_h is keyed on the human (binding.human_id), NOT binding.agent_did:
      // a rotated key re-linked to the same human, or a revoke-then-rebind to
      // the same human, yields the same sub_h per service (§10.4.2, §10.5.1).
      // Never add the agent DID here — it would reopen the §10.5.2 Sybil dedup.
      const subH = deriveSubH(binding.human_id, body.data.aud, pseudonymKeyBytes());

      const { jwt, kid, iat, exp } = await mintAttestationJwt({
        vault,
        agentDid: binding.agent_did,
        serviceDid: body.data.aud,
        verification,
        subH,
      });

      // Best-effort audit + last-used touch.
      await Promise.all([
        store.logIssuedToken({
          binding_id: binding.id,
          service_did: body.data.aud,
          verification,
          kid,
          expires_at: new Date(exp * 1000),
        }),
        store.touchBindingLastUsed(binding.id, new Date(iat * 1000)),
      ]);

      const resp: TokenResponse = {
        jwt,
        expires_at: exp,
        verification,
      };
      return c.json(resp);
    },
  );

  return app;
}

function strongestVerification(
  available: VerificationMethod[],
): VerificationMethod | null {
  const set = new Set(available);
  for (const m of VERIFICATION_RANK) {
    if (set.has(m)) return m;
  }
  return null;
}
