import 'dotenv/config';
import { z } from 'zod';

const ConfigSchema = z.object({
  PORT: z.coerce.number().int().positive().default(3001),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  DATABASE_URL: z.string().url(),
  REDIS_URL: z.string().url(),

  TRUST_SESSION_SECRET: z.string().min(32),
  TRUST_ADMIN_SECRET: z.string().min(16),
  /**
   * Base64 of a 32-byte (256-bit) key-encryption-key used by
   * PgEncryptedKeyVault to wrap signing-key private material at rest.
   * Generate once: `openssl rand -base64 32`.
   *
   * Rotating: decrypt all keys with the old KEK, set the new KEK,
   * re-insert with the new wrapping. Documented in trust/README.md.
   */
  TRUST_KEK_BASE64: z
    .string()
    .refine((s) => {
      try {
        return Buffer.from(s, 'base64').length === 32;
      } catch {
        return false;
      }
    }, 'TRUST_KEK_BASE64 must decode to exactly 32 bytes (use `openssl rand -base64 32`)'),

  /**
   * Cron schedule for scheduled key rotation. Defaults to monthly at
   * 03:00 UTC ("0 3 1 * *"). Set to an empty string to disable the
   * cron entirely; operators can still trigger rotation via
   * `POST /admin/keys/rotate`.
   */
  TRUST_ROTATION_SCHEDULE: z.string().default('0 3 1 * *'),

  PUBLIC_BASE_URL: z.string().url().default('https://trust.afauth.org'),
  JWKS_PUBLIC_URL: z
    .string()
    .url()
    .default('https://trust.afauth.org/.well-known/jwks.json'),

  EMAIL_PROVIDER: z.enum(['stdout', 'resend', 'postmark']).default('stdout'),
  EMAIL_FROM: z.string().email().default('no-reply@trust.afauth.org'),
  EMAIL_API_KEY: z.string().optional(),
});

export type Config = z.infer<typeof ConfigSchema>;

let cached: Config | undefined;

export function getConfig(): Config {
  if (cached) return cached;
  const parsed = ConfigSchema.safeParse(process.env);
  if (!parsed.success) {
    const issues = parsed.error.issues
      .map((i) => `  ${i.path.join('.')}: ${i.message}`)
      .join('\n');
    throw new Error(`Invalid environment configuration:\n${issues}`);
  }
  cached = parsed.data;
  return cached;
}

/** Test-only: reset the cached config so env mutations take effect. */
export function resetConfigForTest(): void {
  cached = undefined;
}
