import 'dotenv/config';
import { z } from 'zod';

const ConfigSchema = z.object({
  PORT: z.coerce.number().int().positive().default(3001),
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace']).default('info'),
  DATABASE_URL: z.string().url(),
  REDIS_URL: z.string().url(),

  /**
   * §10.7: maximum §10 attestation mints per binding per UTC day,
   * across all audiences. Sized for the attested-session re-mint
   * cadence — an agent keeps a fresh attestation on file per service
   * and re-mints ~100×/service/day at the 900s TTL ceiling, so a
   * binding on many `attested_only` services needs well above the old
   * 1,000. Raise it further for very high service fan-out.
   */
  TRUST_PER_BINDING_DAILY_TOKEN_LIMIT: z.coerce.number().int().positive().default(10000),

  TRUST_SESSION_SECRET: z.string().min(32),
  TRUST_ADMIN_SECRET: z.string().min(16),

  /**
   * Number of trusted reverse proxies between the public internet and
   * this service. Used to pick the real client IP from the RIGHT of
   * X-Forwarded-For for rate-limit bucketing (see lib/ratelimit.ts).
   * Default 1 (a single edge proxy such as Railway/Cloudflare); MUST NOT
   * exceed the real proxy depth or a client-forged left entry becomes
   * trusted (audit #6). Read directly from env in ratelimit.ts; declared
   * here for validation + documentation.
   */
  TRUST_TRUSTED_PROXY_HOPS: z.coerce.number().int().min(1).default(1),
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
   * Base64 of a 32-byte HMAC key used to derive the §10.4 `sub_h`
   * pairwise human pseudonym. Generated once and held for the
   * lifetime of the deployment; rotating invalidates every
   * downstream service's per-`sub_h` dedup state and SHOULD be
   * treated as incident response, not routine hygiene (§12.9).
   * Generate: `openssl rand -base64 32`.
   */
  TRUST_PSEUDONYM_KEY_BASE64: z
    .string()
    .refine((s) => {
      try {
        return Buffer.from(s, 'base64').length === 32;
      } catch {
        return false;
      }
    }, 'TRUST_PSEUDONYM_KEY_BASE64 must decode to exactly 32 bytes (use `openssl rand -base64 32`)'),

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

  /**
   * E2E-test escape hatch. When set to `1` or `true`, enables
   * `POST /v1/link/confirm-e2e` — an unauthenticated endpoint that
   * auto-confirms a pending link request for a synthetic human
   * identified only by email. Used exclusively by
   * `spec/harness/e2e/` to drive scenarios without a Playwright
   * browser harness or magic-link round-trip.
   *
   * MUST be unset (or `0`/`false`) in production. The endpoint is
   * a controlled bypass of §10's two-step verify ceremony; with
   * it open, anyone can mint a binding for any agent_did against
   * any email.
   */
  TRUST_E2E_AUTOCONFIRM: z
    .string()
    .default('')
    .transform((v) => v === '1' || v === 'true'),

  EMAIL_PROVIDER: z.enum(['stdout', 'resend', 'postmark']).default('stdout'),
  /**
   * Sender address. Accepts either:
   *   - bare email:        `[email protected]`
   *   - RFC 5322 name-addr: `Display Name <[email protected]>`
   * Resend's `from` field accepts both.
   */
  EMAIL_FROM: z
    .string()
    .refine(
      (s) => {
        const m = s.match(/^\s*(?:[^<>]*<\s*([^>\s]+)\s*>|([^\s<>]+))\s*$/);
        const addr = m?.[1] ?? m?.[2];
        if (!addr) return false;
        // Minimal email shape — exactly one @, non-empty local and
        // domain parts with at least one dot in the domain.
        return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(addr);
      },
      'EMAIL_FROM must be an email or a `Name <email>` name-addr',
    )
    .default('no-reply@trust.afauth.org'),
  EMAIL_API_KEY: z.string().optional(),

  /**
   * Google OAuth credentials. Both are required to enable the
   * "Continue with Google" sign-in option; if either is missing the
   * routes 404 and the UI hides itself. Set in Google Cloud Console →
   * APIs & Services → Credentials → "OAuth 2.0 Client IDs". The
   * registered redirect URI must be `{PUBLIC_BASE_URL}/auth/google/callback`.
   */
  GOOGLE_OAUTH_CLIENT_ID: z.string().optional(),
  GOOGLE_OAUTH_CLIENT_SECRET: z.string().optional(),
}).superRefine((cfg, ctx) => {
  // Hard guard: refuse to boot in production with the e2e escape
  // hatch enabled. A "MUST NOT in production" comment is not an
  // enforcement; this is. See TRUST_E2E_AUTOCONFIRM's doc above for
  // why this matters (it bypasses §10 two-step verify).
  if (cfg.NODE_ENV === 'production' && cfg.TRUST_E2E_AUTOCONFIRM) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      path: ['TRUST_E2E_AUTOCONFIRM'],
      message:
        'TRUST_E2E_AUTOCONFIRM must not be enabled when NODE_ENV=production',
    });
  }
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

/**
 * Returns the Google OAuth credentials iff both env vars are set.
 * Routes and UI use this as the feature gate.
 */
export function getGoogleOauthConfig():
  | { clientId: string; clientSecret: string; redirectUri: string }
  | null {
  const cfg = getConfig();
  if (!cfg.GOOGLE_OAUTH_CLIENT_ID || !cfg.GOOGLE_OAUTH_CLIENT_SECRET) return null;
  return {
    clientId: cfg.GOOGLE_OAUTH_CLIENT_ID,
    clientSecret: cfg.GOOGLE_OAUTH_CLIENT_SECRET,
    redirectUri: `${cfg.PUBLIC_BASE_URL.replace(/\/$/, '')}/auth/google/callback`,
  };
}
