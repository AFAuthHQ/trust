import cron from 'node-cron';
import type { KeyVault } from '../lib/keyvault.js';
import { getLogger } from '../lib/logger.js';
import { MAX_ATTESTATION_TTL_SECONDS } from '../lib/signing.js';

export interface CronHandle {
  stop: () => void;
}

/**
 * Schedules a graceful key rotation: mints a new kid with
 * `activeFrom = now + 900s` so the JWKS publishes it ahead of first
 * use, satisfying AFAP-0006's "publish ≥900s before first use"
 * clause.
 *
 * Does NOT retire old keys automatically — a token issued just
 * before rotation can take up to MAX_ATTESTATION_TTL_SECONDS to
 * drain at consuming services. Operators retire old kids manually
 * via POST /admin/keys/retire once they're confident no in-flight
 * tokens still reference them.
 */
export function startRotationCron(
  vault: KeyVault,
  schedule: string,
): CronHandle | null {
  if (schedule === '') return null;
  if (!cron.validate(schedule)) {
    throw new Error(`Invalid TRUST_ROTATION_SCHEDULE: ${schedule}`);
  }
  const log = getLogger();
  const task = cron.schedule(
    schedule,
    async () => {
      const start = Date.now();
      log.info({ schedule }, 'rotation cron tick');
      try {
        const activeFrom = new Date(Date.now() + MAX_ATTESTATION_TTL_SECONDS * 1000);
        const meta = await vault.rotate({ activeFrom });
        log.info(
          { kid: meta.kid, active_from: meta.activeFrom.toISOString(), ms: Date.now() - start },
          'rotation cron minted new kid',
        );
      } catch (err) {
        log.error({ err }, 'rotation cron failed');
      }
    },
    { scheduled: true },
  );
  return { stop: () => task.stop() };
}
