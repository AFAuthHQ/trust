import type Redis from 'ioredis';
import { TrustError } from './errors.js';
import type { HumanRecord, LinkRequestRecord, Store } from './store/index.js';
import { BINDING_IDLE_TTL_SECONDS, LINK_REQUEST_TTL_SECONDS } from './signing.js';

export interface ConfirmLinkResult {
  link_request: LinkRequestRecord;
  binding_id: string;
  /** When the binding lapses if left unused; re-armed on each mint (binding inactivity window). */
  binding_token_expires_at: Date;
  callback_url: string | null;
}

/**
 * Confirms a pending link request: creates the binding, stashes its
 * id + expiry in Redis under the request id (where /v1/link/poll pops
 * it), and marks the link request confirmed. There is no bearer
 * credential — the agent authenticates future mints by signing with the
 * account key it proved in /v1/link/start (§3.1 keyless mint).
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

  // §10.5 — pre-check that the agent_did isn't already bound by a
  // different human. The store enforces this too (and catches the
  // concurrent-confirm race via SELECT FOR UPDATE / unique index);
  // this read gives a clean, fast rejection in the common case
  // without disclosing which human currently owns the binding.
  const existingActive = await store.findActiveBindingByAgentDid(lr.agent_did);
  if (existingActive && existingActive.human_id !== human.id) {
    throw TrustError.agentAlreadyBound();
  }

  const bindingExpires = new Date(Date.now() + BINDING_IDLE_TTL_SECONDS * 1000);

  const binding = await store.createBinding({
    human_id: human.id,
    agent_did: lr.agent_did,
    agent_label: lr.agent_label ?? undefined,
    agent_pubkey_b64: lr.agent_pubkey_b64,
    expires_at: bindingExpires,
  });

  const confirmed = await store.confirmLinkRequest(lr.id, human.id, binding.id);
  if (!confirmed) throw TrustError.conflict('Failed to confirm link request');

  await redis.setex(
    `binding-token:${lr.id}`,
    LINK_REQUEST_TTL_SECONDS,
    JSON.stringify({
      binding_id: binding.id,
      binding_token_expires_at: Math.floor(bindingExpires.getTime() / 1000),
    }),
  );

  return {
    link_request: confirmed,
    binding_id: binding.id,
    binding_token_expires_at: bindingExpires,
    callback_url: lr.callback_url,
  };
}
