/**
 * "Sign in with AFAuth" — OIDC provider (M2).
 *
 * Proves the producer side: /authorize (PKCE) → code → /token mints an
 * id_token whose `sub` IS the pairwise `sub_h` for (human, service_did),
 * verifiable against the trust JWKS — the exact token artidrop resolves onto
 * the agent-created account.
 */

import { describe, it, expect } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { createTestHarness, setTestEnv } from './helpers.js';
import { listPublicJwks } from '../src/lib/signing.js';
import { hashToken } from '../src/lib/tokens.js';
import { deriveSubH, pseudonymKeyBytes } from '../src/lib/pseudonym.js';
import { assertOidcClients, parseOidcClients } from '../src/lib/oidc-clients.js';

setTestEnv();

const ISSUER = 'http://localhost:3001';
const SERVICE_DID = 'did:web:artidrop.ai';
const CLIENT_ID = 'did:web:artidrop.ai';
const REDIRECT = 'https://api.artidrop.ai/v1/auth/afauth/callback';
const clients = new Map([
  [CLIENT_ID, { clientId: CLIENT_ID, serviceDid: SERVICE_DID, redirectUris: [REDIRECT] }],
]);

function pkce() {
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  return { verifier, challenge };
}

function authorizeUrl(challenge: string, extra: Record<string, string> = {}): string {
  const p = new URLSearchParams({
    client_id: CLIENT_ID,
    redirect_uri: REDIRECT,
    response_type: 'code',
    scope: 'openid',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  });
  return `/oidc/authorize?${p.toString()}`;
}

describe('OIDC discovery', () => {
  it('serves openid-configuration with issuer, endpoints, EdDSA, S256, pairwise', async () => {
    const { app } = await createTestHarness({ oidcClients: clients });
    const res = await app.request('/.well-known/openid-configuration');
    expect(res.status).toBe(200);
    const doc = (await res.json()) as Record<string, unknown>;
    expect(doc.issuer).toBe(ISSUER);
    expect(doc.authorization_endpoint).toBe(`${ISSUER}/oidc/authorize`);
    expect(doc.token_endpoint).toBe(`${ISSUER}/oidc/token`);
    expect(doc.id_token_signing_alg_values_supported).toContain('EdDSA');
    expect(doc.code_challenge_methods_supported).toContain('S256');
    expect(doc.subject_types_supported).toContain('pairwise');
  });
});

describe('OIDC client registry guard (decision §3)', () => {
  it('parseOidcClients round-trips a valid config', () => {
    const reg = parseOidcClients(
      JSON.stringify([{ client_id: CLIENT_ID, service_did: SERVICE_DID, redirect_uris: [REDIRECT] }]),
    );
    expect(reg.get(CLIENT_ID)?.serviceDid).toBe(SERVICE_DID);
  });
  it('empty config → empty registry (no clients)', () => {
    expect(parseOidcClients('').size).toBe(0);
  });
  it('assertOidcClients rejects a non-did:web service_did', () => {
    const reg = new Map([['x', { clientId: 'x', serviceDid: 'not-a-did', redirectUris: [REDIRECT] }]]);
    expect(() => assertOidcClients(reg)).toThrow(/did:web/);
  });
});

describe('OIDC authorize', () => {
  it('unknown client_id → 400 (no redirect)', async () => {
    const { app } = await createTestHarness({ oidcClients: clients });
    const { challenge } = pkce();
    const res = await app.request(
      authorizeUrl(challenge).replace(encodeURIComponent(CLIENT_ID), 'nope'),
    );
    expect(res.status).toBe(400);
  });

  it('unregistered redirect_uri → 400 (never redirects to it)', async () => {
    const { app } = await createTestHarness({ oidcClients: clients });
    const { challenge } = pkce();
    const p = new URLSearchParams({
      client_id: CLIENT_ID,
      redirect_uri: 'https://evil.example.com/cb',
      response_type: 'code',
      scope: 'openid',
      code_challenge: challenge,
      code_challenge_method: 'S256',
    });
    const res = await app.request(`/oidc/authorize?${p.toString()}`);
    expect(res.status).toBe(400);
  });

  it('no session → 302 to /signin with a short rid next', async () => {
    const { app } = await createTestHarness({ oidcClients: clients });
    const { challenge } = pkce();
    const res = await app.request(authorizeUrl(challenge, { state: 'abc' }));
    expect(res.status).toBe(302);
    const loc = res.headers.get('location') ?? '';
    expect(loc).toContain('/signin?next=');
    expect(decodeURIComponent(loc)).toContain('/oidc/authorize?rid=');
  });
});

describe('OIDC full flow → id_token convergence', () => {
  async function signedInHarness() {
    const h = await createTestHarness({ oidcClients: clients });
    const human = await h.store.upsertHuman({ primary_email: 'gaven@example.com' });
    const rawSession = randomBytes(24).toString('hex');
    await h.store.createSession(human.id, hashToken(rawSession), new Date(Date.now() + 3_600_000));
    return { ...h, human, cookie: `trust_sess=${rawSession}` };
  }

  it('authorize → code → token mints an id_token whose sub = deriveSubH(human, service_did)', async () => {
    const { app, vault, human, cookie } = await signedInHarness();
    const { verifier, challenge } = pkce();

    const authRes = await app.request(authorizeUrl(challenge, { state: 'xyz', nonce: 'n1' }), {
      headers: { cookie },
    });
    expect(authRes.status).toBe(302);
    const loc = new URL(authRes.headers.get('location')!);
    expect(`${loc.origin}${loc.pathname}`).toBe(REDIRECT);
    expect(loc.searchParams.get('state')).toBe('xyz');
    const code = loc.searchParams.get('code');
    expect(code).toBeTruthy();

    const tokRes = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT,
      }),
    });
    expect(tokRes.status).toBe(200);
    const tok = (await tokRes.json()) as { id_token: string; token_type: string };
    expect(tok.token_type).toBe('Bearer');

    // Verify the id_token against the published JWKS and assert convergence.
    const jwks = createLocalJWKSet(await listPublicJwks(vault));
    const { payload } = await jwtVerify(tok.id_token, jwks, { issuer: ISSUER, audience: SERVICE_DID });
    expect(payload.sub).toBe(deriveSubH(human.id, SERVICE_DID, pseudonymKeyBytes()));
    expect(payload.nonce).toBe('n1');
  });

  it('the authorization code is single-use', async () => {
    const { app, cookie } = await signedInHarness();
    const { verifier, challenge } = pkce();
    const authRes = await app.request(authorizeUrl(challenge), { headers: { cookie } });
    const code = new URL(authRes.headers.get('location')!).searchParams.get('code');
    const body = JSON.stringify({
      grant_type: 'authorization_code',
      code,
      code_verifier: verifier,
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT,
    });
    const first = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
    });
    expect(first.status).toBe(200);
    const second = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body,
    });
    expect(second.status).toBe(400);
    expect(((await second.json()) as Record<string, unknown>).error).toBe('invalid_grant');
  });

  it('a wrong PKCE verifier is rejected', async () => {
    const { app, cookie } = await signedInHarness();
    const { challenge } = pkce();
    const authRes = await app.request(authorizeUrl(challenge), { headers: { cookie } });
    const code = new URL(authRes.headers.get('location')!).searchParams.get('code');
    const res = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        code_verifier: 'the-wrong-verifier',
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT,
      }),
    });
    expect(res.status).toBe(400);
    expect(((await res.json()) as Record<string, unknown>).error).toBe('invalid_grant');
  });
});

describe('OIDC prompt=consent', () => {
  async function signedInHarness() {
    const h = await createTestHarness({ oidcClients: clients });
    const human = await h.store.upsertHuman({ primary_email: 'gaven@example.com' });
    const rawSession = randomBytes(24).toString('hex');
    await h.store.createSession(human.id, hashToken(rawSession), new Date(Date.now() + 3_600_000));
    return { ...h, human, cookie: `trust_sess=${rawSession}` };
  }
  const ridFrom = (html: string) => /name="rid" value="([^"]+)"/.exec(html)?.[1];

  it('with a live session → renders a consent page, mints NO code yet', async () => {
    const { app, cookie } = await signedInHarness();
    const { challenge } = pkce();
    const res = await app.request(authorizeUrl(challenge, { state: 'xyz', prompt: 'consent' }), {
      headers: { cookie },
    });
    expect(res.status).toBe(200);
    const body = await res.text();
    expect(body).toContain('Authorize sign-in');
    expect(body).toContain('gaven@example.com');
    expect(body).toContain('artidrop.ai'); // RP label derived from redirect host
    expect(ridFrom(body)).toBeTruthy();
  });

  it('approve → 302 to the RP with a code that exchanges for a token', async () => {
    const { app, vault, human, cookie } = await signedInHarness();
    const { verifier, challenge } = pkce();
    const page = await app.request(authorizeUrl(challenge, { state: 'xyz', nonce: 'n1', prompt: 'consent' }), {
      headers: { cookie },
    });
    const rid = ridFrom(await page.text())!;

    const res = await app.request('/oidc/authorize/decision', {
      method: 'POST',
      headers: { cookie, origin: ISSUER, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ rid, decision: 'approve' }).toString(),
    });
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get('location')!);
    expect(`${loc.origin}${loc.pathname}`).toBe(REDIRECT);
    expect(loc.searchParams.get('state')).toBe('xyz');
    const code = loc.searchParams.get('code');
    expect(code).toBeTruthy();

    const tokRes = await app.request('/oidc/token', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        grant_type: 'authorization_code',
        code,
        code_verifier: verifier,
        client_id: CLIENT_ID,
        redirect_uri: REDIRECT,
      }),
    });
    expect(tokRes.status).toBe(200);
    const jwks = createLocalJWKSet(await listPublicJwks(vault));
    const { payload } = await jwtVerify((await tokRes.json() as { id_token: string }).id_token, jwks, {
      issuer: ISSUER,
      audience: SERVICE_DID,
    });
    expect(payload.sub).toBe(deriveSubH(human.id, SERVICE_DID, pseudonymKeyBytes()));
    expect(payload.nonce).toBe('n1');
  });

  it('deny → 302 back to the RP with error=access_denied (no code)', async () => {
    const { app, cookie } = await signedInHarness();
    const { challenge } = pkce();
    const page = await app.request(authorizeUrl(challenge, { state: 'xyz', prompt: 'consent' }), {
      headers: { cookie },
    });
    const rid = ridFrom(await page.text())!;

    const res = await app.request('/oidc/authorize/decision', {
      method: 'POST',
      headers: { cookie, origin: ISSUER, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ rid, decision: 'deny' }).toString(),
    });
    expect(res.status).toBe(302);
    const loc = new URL(res.headers.get('location')!);
    expect(`${loc.origin}${loc.pathname}`).toBe(REDIRECT);
    expect(loc.searchParams.get('error')).toBe('access_denied');
    expect(loc.searchParams.get('state')).toBe('xyz');
    expect(loc.searchParams.get('code')).toBeNull();
  });

  it('no session + prompt=consent → still bounces to /signin (consent deferred to post-auth)', async () => {
    const { app } = await createTestHarness({ oidcClients: clients });
    const { challenge } = pkce();
    const res = await app.request(authorizeUrl(challenge, { prompt: 'consent' }));
    expect(res.status).toBe(302);
    expect(res.headers.get('location') ?? '').toContain('/signin?next=');
  });

  it('a fresh post-signin resume (rid) does NOT re-prompt for consent — the signin was the confirmation', async () => {
    const { app, store } = await createTestHarness({ oidcClients: clients });
    const { challenge } = pkce();
    // No session yet: stashes the areq (prompt=consent) under an rid, bounces to /signin.
    const bounce = await app.request(authorizeUrl(challenge, { state: 's', prompt: 'consent' }));
    const next = new URLSearchParams(bounce.headers.get('location')!.split('?')[1]).get('next')!;
    const rid = new URLSearchParams(next.split('?')[1]).get('rid')!;
    expect(rid).toBeTruthy();

    // "Sign in", then resume via the rid → must issue a code directly, no consent page.
    const human = await store.upsertHuman({ primary_email: 'r@example.com' });
    const rawSession = randomBytes(24).toString('hex');
    await store.createSession(human.id, hashToken(rawSession), new Date(Date.now() + 3_600_000));
    const resume = await app.request(`/oidc/authorize?rid=${rid}`, {
      headers: { cookie: `trust_sess=${rawSession}` },
    });
    expect(resume.status).toBe(302);
    const loc = new URL(resume.headers.get('location')!);
    expect(`${loc.origin}${loc.pathname}`).toBe(REDIRECT);
    expect(loc.searchParams.get('code')).toBeTruthy();
  });
});
