# AFAuth trust attestor

The canonical AFAuth trust attestor at **`trust.afauth.org`**.

This implements the wire surface defined in
[AFAuthHQ/spec → AFAP-0006](https://github.com/AFAuthHQ/spec/blob/main/proposals/0006-afauth-trust-attestor.md):
issuing short-lived, audience-bound JWTs with `iss="afauth-trust"`
that signal a human ↔ agent-DID binding to consuming services.

Verification by consumers is offline against the JWKs document at
`https://trust.afauth.org/.well-known/jwks.json` — served directly
by this service.

## Status

**v0.1.** Email-verified human ↔ agent bindings.

## Stack

- **Runtime**: Node 20 + [Hono](https://hono.dev/) HTTP framework
- **Storage**: Postgres 16 (humans, bindings, signing keys, audit log), Redis 7 (sessions, rate limits, link-request cache)
- **Crypto**: [jose](https://github.com/panva/jose) for EdDSA JWTs and JWKS
- **Hosting**: Railway (production), Docker Compose (local dev)
- **Validation**: Zod
- **Tests**: Vitest

## Local development

```bash
pnpm install

# Postgres on :5433, Redis on :6380 (offset from registry/ so both can run)
docker compose up -d

cp .env.example .env

pnpm migrate
pnpm dev   # :3001
```

Smoke-test:

```bash
curl -s localhost:3001/healthz
# {"status":"ok"}

curl -s localhost:3001/.well-known/jwks.json
# {"keys":[{"kty":"OKP","crv":"Ed25519","kid":"...","x":"..."}]}
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET    | `/healthz`                       | Liveness probe |
| GET    | `/.well-known/jwks.json`         | Public verification keys (cached 300s) |
| GET    | `/`                              | Marketing / landing page |
| GET    | `/link`                          | **Deep-link confirmation page** — humans land here from agents |
| GET    | `/signin`                        | Email magic-link signin |
| POST   | `/signin`                        | Request a magic link |
| GET    | `/signin/callback`               | Consume magic link, set session cookie |
| GET    | `/account`                       | Dashboard: linked agents, verification methods |
| POST   | `/v1/link/start`                 | Agent → returns deep-link URL + poll URL |
| POST   | `/v1/link/confirm`               | Browser (session cookie) → marks link request confirmed |
| POST   | `/v1/link/poll`                  | Agent (signs body) → returns binding token when confirmed |
| POST   | `/v1/token`                      | Agent (bearer binding token) → returns §10 attestation JWT |
| DELETE | `/v1/bindings/:id`               | Human (session cookie) → revokes a binding |

## JWT shape (per AFAP-0006 §10.3.1)

```
header: { alg: "EdDSA", typ: "JWT", kid: "<from jwks.json>" }
claims: {
  iss: "afauth-trust",
  aud: "<service_did>",
  sub: "<agent_did>",
  sub_h: "<base64url HMAC-SHA256 pairwise human pseudonym>",
  iat: <unix>,
  exp: <iat + ≤900>,
  verification: "email" | "oauth" | "payment"
}
```

No PII. The `verification` value is the strongest method the linked
human has on file at issuance time. `sub_h` is a pairwise pseudonym —
stable per `(human, aud)` but unlinkable across services — so a service
can bucket anti-abuse state (quotas, bans) on the human behind an agent
without learning their identity.

## Key management

Signing-key private material is stored in `signing_keys.private_jwk_enc`
as AES-256-GCM ciphertext, decryptable only by holders of
`TRUST_KEK_BASE64`. The public material in `signing_keys.public_jwk` is
unencrypted and served from `/.well-known/jwks.json` as required by
AFAP-0006.

The `KeyVault` interface in `src/lib/keyvault.ts` separates the
"where does the private key live" question from the rest of the
service. Today, `PgEncryptedKeyVault` handles all in-Postgres signing.
Switching to AWS KMS or GCP KMS is a single-file change — the stubs
in `keyvault.ts` document the integration shape.

### Generating a KEK

```bash
openssl rand -base64 32
```

Set as `TRUST_KEK_BASE64` and never commit. In production, source
from a secret manager (Railway secret, AWS Secrets Manager, etc.) so
it never lives in environment templates.

### Rotating the KEK

1. Deploy a new instance with both old and new KEK in env (use a
   one-shot script outside the request path).
2. For each row in `signing_keys`: read ciphertext + IV, decrypt with
   old KEK, re-encrypt with new KEK, write back.
3. Cut traffic over to the new KEK only; remove the old.

Signing keys (the EdDSA keypairs the JWKS publishes) rotate
independently — call `vault.rotate()` from an admin route or cron at
least 900 seconds before the new kid is first used in a token, so
JWKS caches at consuming services have time to refresh.

## Rate limits

Per-IP fixed-window in Redis.

| Endpoint group | Limit |
|---|---|
| `POST /v1/link/start`     | 30 / minute |
| `POST /v1/link/poll`      | 60 / minute |
| `POST /v1/token`          | 60 / minute, 10,000 / day per binding (`TRUST_PER_BINDING_DAILY_TOKEN_LIMIT`, configurable) |
| `POST /signin`            | 5 / minute per IP, 10 / hour per email |
| All others                | 600 / minute |

## Deploying to Railway

1. **New project** → "Deploy from GitHub repo" → `AFAuthHQ/trust`.
2. Add Postgres + Redis plugins (DATABASE_URL / REDIS_URL injected).
3. Set environment variables:
   - `TRUST_SESSION_SECRET` — long random string
   - `TRUST_ADMIN_SECRET`   — long random string
   - `NODE_ENV=production`
   - `LOG_LEVEL=info`
   - `PUBLIC_BASE_URL=https://trust.afauth.org`
   - `JWKS_PUBLIC_URL=https://trust.afauth.org/.well-known/jwks.json`
   - `EMAIL_PROVIDER=<resend|postmark>` and `EMAIL_API_KEY=...`
   - *(optional)* `GOOGLE_OAUTH_CLIENT_ID` + `GOOGLE_OAUTH_CLIENT_SECRET`
     — enables "Continue with Google". Create in Google Cloud Console
     → APIs & Services → Credentials → "OAuth 2.0 Client IDs". Add
     `https://trust.afauth.org/auth/google/callback` as an authorized
     redirect URI. The button hides itself when either env var is
     missing.
4. **Custom domain** → `trust.afauth.org`. This is also the
   AFAP-0006 §10.3.1 JWKS host — consuming services fetch
   `https://trust.afauth.org/.well-known/jwks.json` directly. No
   apex proxy needed.
5. First deploy runs migrations on boot.

## License

Apache-2.0. The specification text this implements is CC-BY-4.0,
hosted in [`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec).
