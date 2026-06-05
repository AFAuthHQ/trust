import { beforeEach, describe, expect, it } from 'vitest';
import {
  SignJWT,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type KeyLike,
} from 'jose';
import { createTestHarness, setTestEnv, type TestHarness } from './helpers.js';

const CLIENT_ID = 'test-client-id.apps.googleusercontent.com';
const GOOGLE_ISSUER = 'https://accounts.google.com';

beforeEach(() => {
  setTestEnv();
  process.env.GOOGLE_OAUTH_CLIENT_ID = CLIENT_ID;
  process.env.GOOGLE_OAUTH_CLIENT_SECRET = 'test-client-secret';
});

/**
 * The Google ID-token verify must pin `algorithms: ['RS256']`. Without
 * the pin, jose resolves whatever key the (attacker-influenceable) JWKS
 * advertises for the token's `alg` — so an ID token signed with a
 * different asymmetric algorithm, accompanied by a matching key, would be
 * accepted. Every other verify path in the service pins its algorithm;
 * this one must too.
 */
describe('Google OIDC verify pins algorithms to RS256', () => {
  it('rejects an ES256-signed ID token even when a matching ES256 key is published', async () => {
    const { publicKey, privateKey } = await generateKeyPair('ES256');
    const pubJwk = await exportJWK(publicKey);
    pubJwk.kid = 'es-kid';
    pubJwk.use = 'sig';
    pubJwk.alg = 'ES256';
    const jwks = createLocalJWKSet({ keys: [pubJwk] });

    let idToken = '';
    const fakeFetch: typeof fetch = async (input, init) => {
      const url = typeof input === 'string' ? input : (input as URL).toString();
      if (url === 'https://oauth2.googleapis.com/token' && init?.method === 'POST') {
        return new Response(
          JSON.stringify({ id_token: idToken, token_type: 'Bearer' }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        );
      }
      return fetch(input, init);
    };

    const { resetConfigForTest } = await import('../src/lib/config.js');
    resetConfigForTest();
    const h: TestHarness = await createTestHarness({
      googleOauthDeps: { fetch: fakeFetch, jwks, issuer: GOOGLE_ISSUER },
    });

    const start = await h.app.request('/auth/google/start', { redirect: 'manual' });
    const url = new URL(start.headers.get('location')!);
    const state = url.searchParams.get('state')!;
    const nonce = url.searchParams.get('nonce')!;
    const stateCookie = (start.headers.get('set-cookie') ?? '').split(';')[0]!;

    const now = Math.floor(Date.now() / 1000);
    idToken = await new SignJWT({
      email: 'esuser@example.com',
      email_verified: true,
      nonce,
    })
      .setProtectedHeader({ alg: 'ES256', kid: 'es-kid' })
      .setIssuer(GOOGLE_ISSUER)
      .setAudience(CLIENT_ID)
      .setSubject('es-sub')
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(privateKey as KeyLike);

    const r = await h.app.request(`/auth/google/callback?code=c&state=${state}`, {
      redirect: 'manual',
      headers: { cookie: stateCookie },
    });

    expect(r.status).toBe(400);
    // The non-RS256 identity must never have been trusted.
    expect(await h.store.getHumanByEmail('esuser@example.com')).toBeNull();
  });
});
