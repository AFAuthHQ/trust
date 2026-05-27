import type Redis from 'ioredis';
import { TrustError } from './errors.js';
import type { HumanRecord, LinkRequestRecord, Store } from './store/index.js';
import { generateToken, hashToken } from './tokens.js';
import { LINK_REQUEST_TTL_SECONDS } from './signing.js';

const BINDING_TTL_SECONDS = 90 * 24 * 60 * 60; // 90 days

export interface ConfirmLinkResult {
  link_request: LinkRequestRecord;
  binding_id: string;
  /** Plaintext binding token — handed once to the agent via Redis pickup. */
  binding_token: string;
  binding_token_expires_at: Date;
  callback_url: string | null;
}

/**
 * Confirms a pending link request: creates the binding, stashes the
 * binding-token raw value in Redis under the request id (where
 * /v1/link/poll pops it), and marks the link request confirmed.
 *
 * Shared between the JSON /v1/link/confirm endpoint and the HTML
 * /link/confirm form handler so the binding semantics live in one
 * place.
 */
export async function confirmLinkRequest(args: {
  store: Store;
  redis: Redis;
  human: HumanRecord;
  reqId: string;
}): Promise<ConfirmLinkResult> {
  const { store, redis, human, reqId } = args;

  const lr = await store.getLinkRequest(reqId);
  if (!lr) throw TrustError.notFound('Link request not found');
  if (lr.state !== 'pending') {
    throw TrustError.conflict(`Link request is ${lr.state}`);
  }
  if (lr.expires_at.getTime() < Date.now()) {
    throw TrustError.gone('Link request expired');
  }

  const bindingTokenRaw = generateToken();
  const bindingTokenHash = hashToken(bindingTokenRaw);
  const bindingExpires = new Date(Date.now() + BINDING_TTL_SECONDS * 1000);

  const binding = await store.createBinding({
    human_id: human.id,
    agent_did: lr.agent_did,
    agent_label: lr.agent_label ?? undefined,
    agent_pubkey_b64: lr.agent_pubkey_b64,
    binding_token_hash: bindingTokenHash,
    expires_at: bindingExpires,
  });

  const confirmed = await store.confirmLinkRequest(lr.id, human.id, binding.id);
  if (!confirmed) throw TrustError.conflict('Failed to confirm link request');

  await redis.setex(
    `binding-token:${lr.id}`,
    LINK_REQUEST_TTL_SECONDS,
    JSON.stringify({
      binding_id: binding.id,
      binding_token: bindingTokenRaw,
      binding_token_expires_at: Math.floor(bindingExpires.getTime() / 1000),
    }),
  );

  return {
    link_request: confirmed,
    binding_id: binding.id,
    binding_token: bindingTokenRaw,
    binding_token_expires_at: bindingExpires,
    callback_url: lr.callback_url,
  };
}
