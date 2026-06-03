-- AFAuth §3.1 — keyless mint. Agents authenticate POST /v1/token by
-- signing the request with their account key (RFC 9421 / §5), verified
-- offline against the did:key keyid, instead of presenting a bearer
-- binding_token. The token is removed entirely (no dual-accept): the
-- keypair is the sole credential, so there is no standing secret to
-- store or leak.
--
-- The binding_token_hash column is therefore dead — nothing writes it
-- (createBinding no longer sets it) and nothing reads it
-- (getBindingByTokenHash is removed). Drop it. Bindings remain keyed on
-- agent_did (the §10.5 one-active-binding-per-agent-DID unique index),
-- which is what the mint path looks up by the verified keyid.

ALTER TABLE bindings DROP COLUMN IF EXISTS binding_token_hash;
