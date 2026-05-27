import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { getConfig } from '../src/lib/config.js';

async function main(): Promise<void> {
  const cfg = getConfig();
  const pool = new Pool({ connectionString: cfg.DATABASE_URL });

  const dir = join(process.cwd(), 'migrations');
  const files = (await readdir(dir)).filter((f) => f.endsWith('.sql')).sort();

  const redacted = cfg.DATABASE_URL.replace(/:[^:@]+@/, ':***@');
  console.log(`Running ${files.length} migration(s) against ${redacted}`);

  for (const file of files) {
    const sql = await readFile(join(dir, file), 'utf8');
    console.log(`  → ${file}`);
    await pool.query(sql);
  }

  await pool.end();
  console.log('Done.');
}

main().catch((err) => {
  console.error('Migration failed:', err);
  process.exit(1);
});
