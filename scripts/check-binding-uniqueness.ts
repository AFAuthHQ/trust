/**
 * Pre-migration check for migration 0004_binding_uniqueness.sql.
 *
 * Before that migration ran, the bindings table allowed multiple
 * humans to bind the same agent_did (one row per (human_id, agent_did)
 * pair). Migration 0004 replaces that with a partial unique index on
 * agent_did WHERE revoked_at IS NULL — so any pre-existing rows that
 * violate the new rule will cause CREATE UNIQUE INDEX to fail.
 *
 * In practice the duplicate case is unlikely to have occurred, but
 * run this once against any environment that ran the old schema in
 * production before merging the migration.
 *
 *   pnpm tsx scripts/check-binding-uniqueness.ts
 */
import { Pool } from 'pg';
import { getConfig } from '../src/lib/config.js';

async function main(): Promise<void> {
  const pool = new Pool({ connectionString: getConfig().DATABASE_URL });
  try {
    const { rows } = await pool.query<{
      agent_did: string;
      n: string;
      human_ids: string[];
    }>(`
      SELECT agent_did, COUNT(*)::text AS n, array_agg(human_id::text) AS human_ids
      FROM bindings
      WHERE revoked_at IS NULL
      GROUP BY agent_did
      HAVING COUNT(*) > 1
      ORDER BY n DESC, agent_did
    `);

    if (rows.length === 0) {
      console.log('OK — no agent_did has multiple active bindings.');
      console.log('Safe to run migration 0004_binding_uniqueness.sql.');
      return;
    }

    console.error(
      `FAIL — ${rows.length} agent_did(s) have multiple active bindings:`,
    );
    for (const r of rows) {
      console.error(`  ${r.agent_did} (${r.n} bindings): ${r.human_ids.join(', ')}`);
    }
    console.error('');
    console.error(
      'Resolve before running migration 0004: revoke all but one binding per agent_did.',
    );
    console.error('CREATE UNIQUE INDEX will fail otherwise.');
    process.exit(1);
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error('Check failed:', err);
  process.exit(1);
});
