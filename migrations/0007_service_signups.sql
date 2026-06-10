-- Connected-services ledger (core.md §10.3.1 / §8.5).
--
-- service_signups - one row per (agent_did, service_did) the attestor has
--                   minted an attestation for, with the first-mint time and a
--                   per-pair revoke flag. The owner sees this list on /account
--                   and may revoke minting for an individual pair; a revoked
--                   pair is refused at POST /v1/token with `service_suspended`.
--                   Owner-scoped audit data (§13.3): keyed to the human via
--                   human_id, cascade-deleted with the human.
--
-- Distinct from token_log, which is an append-only per-mint audit with no
-- revoke state: this is the deduped, mutable per-pair record the owner controls.
-- The UNIQUE (agent_did, service_did) is the mint-path lookup key — an agent_did
-- has at most one active binding (§10.5), so the pair resolves to one human.

CREATE TABLE IF NOT EXISTS service_signups (
  id           bigserial PRIMARY KEY,
  human_id     uuid NOT NULL REFERENCES humans(id) ON DELETE CASCADE,
  agent_did    text NOT NULL,
  service_did  text NOT NULL,
  first_seen   timestamptz NOT NULL DEFAULT now(),
  last_seen    timestamptz NOT NULL DEFAULT now(),
  revoked_at   timestamptz,
  UNIQUE (agent_did, service_did)
);
CREATE INDEX IF NOT EXISTS service_signups_human_idx ON service_signups (human_id);
