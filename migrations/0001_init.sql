-- AFAP-0006: trust attestor schema.
--
-- humans          - one row per human account at trust.afauth.org
-- verifications   - one row per (human, method, provider) — list-shaped
--                   so v0.2/v0.3 (oauth, payment) can append rows
-- sessions        - browser session for the dashboard / link confirm UI
-- magic_links     - email-magic-link single-use tokens (v0.1)
-- link_requests   - the deep-link "agent wants to bind" pending state
-- bindings        - confirmed (human, agent_did) pair, holds the
--                   long-lived binding-token hash the agent presents
--                   when calling POST /v1/token
-- signing_keys    - rotating Ed25519 keypairs whose public material is
--                   exposed via /.well-known/jwks.json
-- token_log       - audit log of issued §10 attestation JWTs (no PII)

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS humans (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  primary_email   text NOT NULL UNIQUE,
  created_at      timestamptz NOT NULL DEFAULT now(),
  disabled_at     timestamptz
);

CREATE TABLE IF NOT EXISTS verifications (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  human_id        uuid NOT NULL REFERENCES humans(id) ON DELETE CASCADE,
  method          text NOT NULL CHECK (method IN ('email','oauth','payment')),
  provider        text NOT NULL,
  verified_at     timestamptz NOT NULL DEFAULT now(),
  revoked_at      timestamptz,
  UNIQUE (human_id, method, provider)
);
CREATE INDEX IF NOT EXISTS verifications_human_idx ON verifications (human_id);

CREATE TABLE IF NOT EXISTS sessions (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  human_id        uuid NOT NULL REFERENCES humans(id) ON DELETE CASCADE,
  token_hash      text NOT NULL UNIQUE,
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  last_seen_at    timestamptz NOT NULL DEFAULT now(),
  ip              text,
  user_agent      text
);
CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions (expires_at);

CREATE TABLE IF NOT EXISTS magic_links (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email           text NOT NULL,
  token_hash      text NOT NULL UNIQUE,
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  consumed_at     timestamptz,
  next_path       text
);
CREATE INDEX IF NOT EXISTS magic_links_expires_idx ON magic_links (expires_at);

CREATE TABLE IF NOT EXISTS link_requests (
  id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  agent_did       text NOT NULL,
  agent_label     text,
  agent_pubkey_b64 text NOT NULL,
  state           text NOT NULL CHECK (state IN ('pending','confirmed','expired','canceled')),
  human_id        uuid REFERENCES humans(id) ON DELETE SET NULL,
  binding_id      uuid,
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  confirmed_at    timestamptz,
  callback_url    text
);
CREATE INDEX IF NOT EXISTS link_requests_state_idx ON link_requests (state, expires_at);

CREATE TABLE IF NOT EXISTS bindings (
  id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  human_id            uuid NOT NULL REFERENCES humans(id) ON DELETE CASCADE,
  agent_did           text NOT NULL,
  agent_label         text,
  agent_pubkey_b64    text NOT NULL,
  binding_token_hash  text NOT NULL UNIQUE,
  created_at          timestamptz NOT NULL DEFAULT now(),
  expires_at          timestamptz NOT NULL,
  revoked_at          timestamptz,
  last_used_at        timestamptz,
  UNIQUE (human_id, agent_did)
);
CREATE INDEX IF NOT EXISTS bindings_human_idx ON bindings (human_id);
CREATE INDEX IF NOT EXISTS bindings_agent_did_idx ON bindings (agent_did);

CREATE TABLE IF NOT EXISTS signing_keys (
  kid             text PRIMARY KEY,
  alg             text NOT NULL,
  public_jwk      jsonb NOT NULL,
  private_jwk     jsonb NOT NULL,  -- TODO: move to KMS for production
  created_at      timestamptz NOT NULL DEFAULT now(),
  active_from     timestamptz NOT NULL,
  retired_at      timestamptz
);
CREATE INDEX IF NOT EXISTS signing_keys_active_idx ON signing_keys (active_from) WHERE retired_at IS NULL;

CREATE TABLE IF NOT EXISTS token_log (
  id              bigserial PRIMARY KEY,
  binding_id      uuid NOT NULL REFERENCES bindings(id) ON DELETE CASCADE,
  service_did     text NOT NULL,
  verification    text NOT NULL,
  kid             text NOT NULL,
  issued_at       timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS token_log_binding_idx ON token_log (binding_id, issued_at DESC);
