-- Backfill the connected-services ledger (0007) from token_log history.
--
-- service_signups is populated going forward by recordServiceSignup on each
-- mint (token.ts). But an account that was already minting before 0007 shipped
-- shows an EMPTY Signups list until its next mint — even though token_log
-- already holds its full per-mint history (binding_id, service_did, issued_at).
-- Seed one row per (agent_did, service_did) from that history so the owner sees
-- where their agents are already signed up, with an accurate first_seen.
--
-- Idempotent: ON CONFLICT DO NOTHING leaves rows already created by runtime
-- mints — and any owner revoke state on them — untouched. On a fresh database
-- token_log is empty, so this is a no-op. Re-runs re-aggregate token_log but
-- insert nothing new; once existing deployments are seeded this migration may
-- be removed (runtime recording keeps the ledger current from here on).

INSERT INTO service_signups (human_id, agent_did, service_did, first_seen, last_seen)
SELECT b.human_id, b.agent_did, t.service_did, MIN(t.issued_at), MAX(t.issued_at)
  FROM token_log t
  JOIN bindings b ON b.id = t.binding_id
 GROUP BY b.human_id, b.agent_did, t.service_did
ON CONFLICT (agent_did, service_did) DO NOTHING;
