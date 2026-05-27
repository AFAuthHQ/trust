-- Move signing-key private material from cleartext JWK to AES-256-GCM
-- ciphertext, decryptable only by holders of TRUST_KEK_BASE64.
--
-- AFAP-0006 §10.3.1 mandates offline verification against the JWKS
-- document — the public material in `public_jwk` is unchanged. This
-- migration only affects the private material at rest. Token issuance
-- still happens in-process; the KeyVault decrypts the private JWK on
-- demand and never persists it back.
--
-- Drop-then-add is acceptable because:
--   - signing_keys has no production data
--   - any pre-migration row would be unrecoverable anyway (the schema
--     change shifts the encryption boundary)
--
-- IF EXISTS / IF NOT EXISTS clauses keep this idempotent so
-- PgStore.init() can re-run every boot without erroring on the
-- second pass.

ALTER TABLE signing_keys DROP COLUMN IF EXISTS private_jwk;

ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS private_jwk_enc bytea NOT NULL DEFAULT '\x'::bytea;
ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS private_jwk_iv  bytea NOT NULL DEFAULT '\x'::bytea;

-- Drop the harmless defaults now that the columns exist; new inserts
-- MUST supply real bytes. ALTER ... DROP DEFAULT is no-op when no
-- default is set, so this is idempotent.
ALTER TABLE signing_keys ALTER COLUMN private_jwk_enc DROP DEFAULT;
ALTER TABLE signing_keys ALTER COLUMN private_jwk_iv DROP DEFAULT;
