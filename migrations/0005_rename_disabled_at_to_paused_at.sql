-- Owner kill-switch terminology: the owner-facing self-service control
-- is "Pause" / "Resume" (reversible) rather than "Disable" / "Re-enable".
-- See src/views/account.ts and AFAP-0006 §8.4. The wire code is
-- `account_paused`; rename the storage column to match.
--
-- Idempotent: store.init() re-runs every migration file on each boot, so
-- the rename is guarded to no-op once `paused_at` already exists. On a
-- fresh DB, 0001 creates `disabled_at`, then this renames it to `paused_at`.
--
-- Operator-initiated take-down (a separate, future action) is a distinct
-- concept and is intentionally NOT covered by this column.
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'humans' AND column_name = 'disabled_at'
  ) AND NOT EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_name = 'humans' AND column_name = 'paused_at'
  ) THEN
    ALTER TABLE humans RENAME COLUMN disabled_at TO paused_at;
  END IF;
END $$;
