-- AFAP-0006 §10.5 — agent–principal binding uniqueness.
--
-- Previous schema allowed multiple humans to bind the same agent_did
-- (one row per (human_id, agent_did) pair). That defeats §10.4's
-- sub_h dedup property: a single agent could present different
-- sub_h values at a service by rotating among its bindings.
--
-- New rule: at most one ACTIVE binding per agent_did per attestor.
-- A revoked binding stays in the table for audit but does not block
-- a new binding for the same agent_did (allows operator handoff via
-- explicit revoke + re-link, per §10.5.1).
--
-- Pre-migration: if any agent_did currently has >1 active binding,
-- the CREATE UNIQUE INDEX below will fail. Operators MUST resolve
-- such rows manually first (see scripts/check-binding-uniqueness.ts).

ALTER TABLE bindings DROP CONSTRAINT IF EXISTS bindings_human_id_agent_did_key;

CREATE UNIQUE INDEX IF NOT EXISTS bindings_active_agent_did_idx
  ON bindings (agent_did)
  WHERE revoked_at IS NULL;
