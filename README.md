# AFAuth trust attestor

> The reference trust attestor for the [AFAuth Protocol](https://github.com/AFAuthHQ/spec) — **Agent-First Auth**, the open protocol that makes AI agents first-class citizens of every service.

Spam-resistant AFAuth services can require that a request be backed by a real human — without ever learning *which* human. This service makes that binding: a person proves control of an email address (or Google account), an agent links its DID to that person, and the attestor issues short-lived, audience-bound JWTs attesting that a verified human stands behind the agent. The token carries a *pairwise pseudonym*, never an identity.

This repository is the canonical attestor at **[`trust.afauth.org`](https://trust.afauth.org)**, implementing [AFAP-0006](https://github.com/AFAuthHQ/spec/blob/main/proposals/0006-afauth-trust-attestor.md). Consuming services verify tokens **offline** against the JWKS at [`/.well-known/jwks.json`](https://trust.afauth.org/.well-known/jwks.json), served directly by this service.

**Part of AFAuth:** [Protocol spec](https://github.com/AFAuthHQ/spec) · [Docs](https://docs.afauth.org) · [CLI](https://github.com/AFAuthHQ/cli) · [SDK](https://github.com/AFAuthHQ/typescript-sdk) · [Service directory](https://github.com/AFAuthHQ/registry)

- **Relying on this attestor?** See who runs it and what they commit to — [operator commitment](https://trust.afauth.org/operator), [take-down policy](https://trust.afauth.org/policy), and the [security policy](https://github.com/AFAuthHQ/.github/blob/main/SECURITY.md).
- **Running your own?** [AFAP-0007](https://github.com/AFAuthHQ/spec/blob/main/proposals/0007-refresh-recognized-attestors.md) recognizes multiple attestors — see [Run your own instance](#run-your-own-instance).

## Contents

- [Status](#status)
- [Trust & privacy model](#trust--privacy-model)
- [JWT shape](#jwt-shape-per-afap-0006-1031)
- [Architecture](#architecture)
- [Stack](#stack)
- [Local development](#local-development)
- [Endpoints](#endpoints)
- [Sign in with AFAuth (OIDC IdP)](#sign-in-with-afauth-oidc-idp)
- [Configuration](#configuration)
- [Key management](#key-management)
- [Rate limits](#rate-limits)
- [Run your own instance](#run-your-own-instance)
- [Contributing](#contributing)
- [License](#license)

## Status

**v0.1.** Email- and Google-verified human ↔ agent bindings.

## Trust & privacy model

A consuming service trusts this attestor *without* trusting it with identity. Two properties make that safe:

- **No PII leaves the boundary.** A token's `sub_h` claim is a pairwise HMAC pseudonym — stable per `(human, audience)` but unlinkable across services. A service can bucket anti-abuse state (quotas, bans, reputation) on the human behind an agent without ever learning who they are.
- **Offline verification.** Consumers fetch the JWKS once, cache it, and validate `iss`, `aud`, `exp`, and the signature locally. There is no per-request callback to this service, so it never learns who consumes a token.

Accountability runs the other way too: the operator publishes an [operator commitment](https://trust.afauth.org/operator) and a [take-down policy](https://trust.afauth.org/policy), follows the AFAuth [security policy](https://github.com/AFAuthHQ/.github/blob/main/SECURITY.md) for coordinated disclosure, and lets any human revoke a binding from their [dashboard](https://trust.afauth.org/account) at any time.

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

No PII. `verification` is the strongest method the linked human has on
file at issuance time. See [Trust & privacy model](#trust--privacy-model)
for how `sub_h` lets a service bucket anti-abuse state without learning
identity.

## Architecture

A single [Hono](https://hono.dev/) service:

- **`src/routes/`** — the HTTP surface: the link ceremony (`/v1/link/*`), token issuance (`/v1/token`), binding revocation, the human dashboard with email magic-link and Google sign-in, the public JWKS, the governance pages, and operator-only key admin.
- **`src/lib/`** — crypto and storage: `signing` + `keyvault` (EdDSA keys, encrypted at rest), `pseudonym` (the `sub_h` HMAC), `agent-sig` / `request-sig` (verifying agent-signed requests), and `store/` (Postgres in production).
- **`src/jobs/rotation.ts`** — signing-key rotation.

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
| GET    | `/signin`                        | Email magic-link sign-in |
| POST   | `/signin`                        | Request a magic link |
| GET    | `/signin/callback`               | Consume magic link, set session cookie |
| POST   | `/signout`                       | Clear the session |
| GET    | `/account`                       | Dashboard: linked agents, verification methods |
| POST   | `/v1/link/start`                 | Agent → returns deep-link URL + poll URL |
| POST   | `/v1/link/confirm`               | Browser (session cookie) → marks link request confirmed |
| POST   | `/v1/link/poll`                  | Agent (signs body) → returns binding token when confirmed |
| POST   | `/v1/token`                      | Agent (bearer binding token) → returns §10 attestation JWT |
| DELETE | `/v1/bindings/:id`               | Human (session cookie) → revokes a binding |

When Google OAuth is configured (see [Configuration](#configuration)),
three more routes mount; the "Continue with Google" button hides itself
when it isn't:

| Method | Path | Purpose |
|---|---|---|
| GET    | `/auth/google/start`    | Begin "Continue with Google" |
| GET    | `/auth/google/callback` | OAuth redirect target |
| POST   | `/auth/google/revoke`   | Disconnect Google from an account |

When OIDC clients are registered (`TRUST_OIDC_CLIENTS`), the attestor also acts
as an **OpenID Provider** for [Sign in with AFAuth](#sign-in-with-afauth-oidc-idp):

| Method | Path | Purpose |
|---|---|---|
| GET  | `/.well-known/openid-configuration` | OIDC discovery document (cached 300s) |
| GET  | `/oidc/authorize`                   | Human sign-in — Authorization Code + PKCE (`S256`) |
| POST | `/oidc/token`                       | Exchange the auth code for an `id_token` |

## Sign in with AFAuth (OIDC IdP)

Beyond agent attestation, the trust attestor doubles as an **OpenID Provider** so
a consuming service can offer human **Sign in with AFAuth**: a human signs in and
lands in the *same account their agent created*. An AFAuth account is keyed on the
pairwise principal `(iss, sub_h)` — which is exactly an OIDC `(issuer, subject)` —
so the `id_token`'s `sub` is the very `sub_h` this attestor mints in an attestation
for that `(human, service)`. Normative shape: [`spec/core.md` §10.8](https://github.com/AFAuthHQ/spec/blob/main/spec/core.md#108-human-sign-in-via-the-trust-attestor-openid-provider)
(AFAP-0008). Service-side how-to: [Add Sign in with AFAuth](https://docs.afauth.org/guides/add-sign-in-with-afauth).

Standard Authorization Code + PKCE (`S256`); the OIDC keys are the same JWKS used
for attestation. The `id_token`:

```
header: { alg: "EdDSA", typ: "JWT", kid: "<from jwks.json>" }
claims: {
  iss:   "https://trust.afauth.org",   // a URL — NOT the bare "afauth-trust" of an attestation
  aud:   "<service_did>",
  sub:   "<sub_h — identical to the attestation's sub_h for this (human, service)>",
  iat:   <unix>,
  exp:   <unix>,
  nonce: "<echoed if supplied>"
}
```

**Issuer note.** An attestation's `iss` is the bare string `afauth-trust`; the
`id_token`'s `iss` is the URL `https://trust.afauth.org`. They denote the same
attestor, so a relying party that keys accounts on `(iss, sub_h)` MUST canonicalize
both to one issuer before lookup (§10.8.4) — otherwise the human lands in a new,
empty account. No PII is ever placed in the `id_token`.

### Registering a client

Set `TRUST_OIDC_CLIENTS` to a JSON array of the services allowed to use sign-in:

```json
[
  {
    "client_id":     "did:web:api.example.com",
    "service_did":   "did:web:api.example.com",
    "redirect_uris": ["https://api.example.com/auth/afauth/callback"]
  }
]
```

- `service_did` **MUST equal** the value the service uses as the attestation `aud`
  — it is the audience input to the `sub_h` derivation, so a mismatch lands the
  human in a different (empty) account.
- `redirect_uris` is an exact allowlist; an authorization request with any other
  redirect is rejected before a code is issued.
- Validation is fail-closed at boot: a malformed entry stops startup.

## Configuration

The full template is in [`.env.example`](.env.example). On Railway,
`DATABASE_URL` and `REDIS_URL` are injected by the Postgres and Redis
plugins. **Source every secret from a secret manager — never an env
template committed to the repo.**

| Variable | Required | Purpose |
|---|---|---|
| `DATABASE_URL`               | ✅ (injected on Railway) | Postgres connection string. |
| `REDIS_URL`                  | ✅ (injected on Railway) | Redis connection string. |
| `TRUST_SESSION_SECRET`       | ✅ | Signs human-dashboard session cookies. 32+ random bytes. |
| `TRUST_KEK_BASE64`           | ✅ | AES-256-GCM key-encryption-key protecting signing-key private material at rest. `openssl rand -base64 32` (must decode to exactly 32 bytes). See [Key management](#key-management). |
| `TRUST_PSEUDONYM_KEY_BASE64` | ✅ | HMAC key deriving the `sub_h` pairwise pseudonyms. `openssl rand -base64 32`, **distinct** from the KEK. Rotating it invalidates every consumer's per-`sub_h` dedup state — treat as incident response, not routine hygiene. |
| `TRUST_ADMIN_SECRET`         | ✅ | Bearer secret for the operator-only `/admin/keys/*` routes. |
| `PUBLIC_BASE_URL`            | ✅ | Public origin; used for absolute URLs in deep links. |
| `JWKS_PUBLIC_URL`            | ✅ | Canonical JWKS URL advertised on the landing page (AFAP-0006 pins it to `https://trust.afauth.org/.well-known/jwks.json`). |
| `EMAIL_PROVIDER`             | ✅ | `resend` \| `postmark` \| `stdout`. `stdout` prints the magic link to the server log (dev only). |
| `EMAIL_FROM`                 | ✅ | Magic-link sender address. |
| `EMAIL_API_KEY`              | if provider ≠ `stdout` | Email provider API key. |
| `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` | optional | Enables "Continue with Google". Both required together; the button hides when either is unset. |
| `TRUST_OIDC_CLIENTS`         | optional | JSON array registering OIDC relying parties for [Sign in with AFAuth](#sign-in-with-afauth-oidc-idp): `[{client_id, service_did, redirect_uris[]}]`. Unset → the OIDC endpoints accept no clients. `service_did` must match the client's attestation `aud`. Validated fail-closed at boot. |
| `NODE_ENV`                   | optional | `production` in production. |
| `LOG_LEVEL`                  | optional | `info` default. |
| `PORT`                       | optional | Defaults to 3001. |

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

### Rotating signing keys

Signing keys (the EdDSA keypairs the JWKS publishes) rotate
independently of the KEK. Operator-only and bearer `TRUST_ADMIN_SECRET`:

| Method | Path | Purpose |
|---|---|---|
| GET  | `/admin/keys`        | List signing keys and their state |
| POST | `/admin/keys/rotate` | Mint a new active signing key |
| POST | `/admin/keys/retire` | Retire an old key |

Rotate at least 900 seconds before the new `kid` is first used in a
token, so JWKS caches at consuming services have time to refresh.

## Rate limits

Per-IP fixed-window in Redis.

| Endpoint group | Limit |
|---|---|
| `POST /v1/link/start`     | 30 / minute |
| `POST /v1/link/poll`      | 60 / minute |
| `POST /v1/token`          | 60 / minute, 10,000 / day per binding (`TRUST_PER_BINDING_DAILY_TOKEN_LIMIT`, configurable) |
| `POST /signin`            | 5 / minute per IP, 10 / hour per email |
| All others                | 600 / minute |

## Run your own instance

[AFAP-0007](https://github.com/AFAuthHQ/spec/blob/main/proposals/0007-refresh-recognized-attestors.md)
recognizes multiple trust attestors, so you can run your own — for a
private agent fleet or as an alternative public attestor. The canonical
instance runs on Railway, but any container host works (a
[`Dockerfile`](Dockerfile) is included). Note that consumers **pin** the
JWKS URLs they trust, so a self-hosted attestor is honored only by
services that explicitly recognize it.

From the Railway dashboard:

1. **New project** → "Deploy from GitHub repo" → `AFAuthHQ/trust`.
2. Add **Postgres** + **Redis** plugins (`DATABASE_URL` / `REDIS_URL`
   injected automatically).
3. Set the environment variables from the [Configuration](#configuration)
   table. At minimum: `TRUST_SESSION_SECRET`, `TRUST_KEK_BASE64`,
   `TRUST_PSEUDONYM_KEY_BASE64`, `TRUST_ADMIN_SECRET`, `PUBLIC_BASE_URL`,
   `JWKS_PUBLIC_URL`, `EMAIL_PROVIDER`, `EMAIL_FROM`, `NODE_ENV=production`.
   - *(optional)* `GOOGLE_OAUTH_CLIENT_ID` + `GOOGLE_OAUTH_CLIENT_SECRET`
     enable "Continue with Google". Create them in Google Cloud Console
     → APIs & Services → Credentials → "OAuth 2.0 Client IDs", and
     register `{PUBLIC_BASE_URL}/auth/google/callback` as an authorized
     redirect URI.
4. **Custom domain** → `trust.afauth.org` (or your own). This host also
   serves the AFAP-0006 §10.3.1 JWKS — consuming services fetch
   `/.well-known/jwks.json` from it directly. No apex proxy needed.
5. First deploy runs migrations on boot.

## Contributing

The token format and link ceremony are defined by the protocol, not this
repo — to change *behavior*, propose an [AFAP](https://github.com/AFAuthHQ/spec/tree/main/proposals)
against [`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec). Bug reports
and fixes against this implementation are welcome as issues and PRs here.
Because this service mints identity-binding tokens and stores human
contact data, **please report security issues privately** per the
[AFAuth security policy](https://github.com/AFAuthHQ/.github/blob/main/SECURITY.md)
— do not open a public issue.

## License

[Apache-2.0](LICENSE). The specification text this implements is
CC-BY-4.0, hosted in [`AFAuthHQ/spec`](https://github.com/AFAuthHQ/spec).
