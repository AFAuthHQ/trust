-- AFAP-0006 v0.2: OAuth verification (Google).
--
-- The verifications row for an OAuth provider needs to pin the
-- upstream subject identifier ("sub" claim in Google's ID token), not
-- just the email. The email is mutable on the provider's side; the
-- subject is the stable identity. Pinning the subject prevents:
--   (a) a second human linking the same Google account (hijack)
--   (b) a primary-email change on the trust side from silently
--       severing the upstream binding

ALTER TABLE verifications
  ADD COLUMN IF NOT EXISTS external_subject text;

-- One human per (provider, subject). Partial index so existing
-- email-method rows (external_subject NULL) don't trip the constraint.
CREATE UNIQUE INDEX IF NOT EXISTS verifications_provider_subject_idx
  ON verifications (provider, external_subject)
  WHERE external_subject IS NOT NULL;
