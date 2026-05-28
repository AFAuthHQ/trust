import { beforeEach, describe, expect, it } from 'vitest';
import {
  SignJWT,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  type KeyLike,
} from 'jose';
import { setTestEnv, createTestHarness, type TestHarness } from './helpers.js';

const CLIENT_ID = 'test-client-id.apps.googleusercontent.com';
const CLIENT_SECRET = 'test-client-secret';
const GOOGLE_ISSUER = 'https://accounts.google.com';

interface FakeGoogle {
  /** Drop-in for global fetch — intercepts only the token endpoint. */
  fetch: typeof fetch;
  /** JWKS the OAuth client should use to verify our fake ID tokens. */
  jwks: ReturnType<typeof createLocalJWKSet>;
  /** Build a Google-style ID token for the given identity. */
  mintIdToken: (opts: {
    sub: string;
    email: string;
    email_verified: boolean;
    nonce: string;
    aud?: string;
    expSec?: number;
  }) => Promise<string>;
  /** Set what the next /token call should return. */
  setNextTokenResponse: (idToken: string | { error: string }) => void;
}

async function makeFakeGoogle(): Promise<FakeGoogle> {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const pubJwk = await exportJWK(publicKey);
  pubJwk.kid = 'test-kid-1';
  pubJwk.use = 'sig';
  pubJwk.alg = 'RS256';
  const jwks = createLocalJWKSet({ keys: [pubJwk] });

  let nextResponse: string | { error: string } | null = null;

  const fakeFetch: typeof fetch = async (input, init) => {
    const url = typeof input === 'string' ? input : (input as URL).toString();
    if (url === 'https://oauth2.googleapis.com/token' && init?.method === 'POST') {
      if (!nextResponse) {
        return new Response(JSON.stringify({ error: 'no_response_queued' }), {
          status: 500,
          headers: { 'content-type': 'application/json' },
        });
      }
      const r = nextResponse;
      nextResponse = null;
      if (typeof r === 'string') {
        return new Response(JSON.stringify({ id_token: r, token_type: 'Bearer' }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      }
      return new Response(JSON.stringify(r), {
        status: 400,
        headers: { 'content-type': 'application/json' },
      });
    }
    // Pass-through to real fetch for anything else (nothing should
    // happen, but don't accidentally swallow it).
    return fetch(input, init);
  };

  return {
    fetch: fakeFetch,
    jwks,
    mintIdToken: async (opts) => {
      const now = Math.floor(Date.now() / 1000);
      return new SignJWT({
        email: opts.email,
        email_verified: opts.email_verified,
        nonce: opts.nonce,
      })
        .setProtectedHeader({ alg: 'RS256', kid: 'test-kid-1' })
        .setIssuer(GOOGLE_ISSUER)
        .setAudience(opts.aud ?? CLIENT_ID)
        .setSubject(opts.sub)
        .setIssuedAt(now)
        .setExpirationTime(now + (opts.expSec ?? 3600))
        .sign(privateKey as KeyLike);
    },
    setNextTokenResponse: (r) => {
      nextResponse = r;
    },
  };
}

beforeEach(() => {
  setTestEnv();
  process.env.GOOGLE_OAUTH_CLIENT_ID = CLIENT_ID;
  process.env.GOOGLE_OAUTH_CLIENT_SECRET = CLIENT_SECRET;
});

// resetConfigForTest is imported lazily so the env vars are in place
// before any module-load-time getConfig() calls.
async function freshHarness(google: FakeGoogle): Promise<TestHarness> {
  const { resetConfigForTest } = await import('../src/lib/config.js');
  resetConfigForTest();
  return createTestHarness({
    googleOauthDeps: {
      fetch: google.fetch,
      jwks: google.jwks,
      issuer: GOOGLE_ISSUER,
    },
  });
}

describe('GET /auth/google/start', () => {
  it('redirects to Google with PKCE + state, stashes pending state in Redis', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const r = await h.app.request('/auth/google/start?next=%2Faccount', {
      redirect: 'manual',
    });
    expect(r.status).toBe(302);
    const loc = r.headers.get('location') ?? '';
    expect(loc).toContain('https://accounts.google.com/o/oauth2/v2/auth');
    expect(loc).toContain('response_type=code');
    expect(loc).toContain(`client_id=${encodeURIComponent(CLIENT_ID)}`);
    expect(loc).toContain('code_challenge=');
    expect(loc).toContain('code_challenge_method=S256');
    expect(loc).toContain('scope=openid+email+profile');

    const url = new URL(loc);
    const state = url.searchParams.get('state')!;
    expect(state).toBeTruthy();
    const pending = await h.redis.get(`oauth:google:state:${state}`);
    expect(pending).toBeTruthy();
    const parsed = JSON.parse(pending!);
    expect(parsed.codeVerifier).toBeTruthy();
    expect(parsed.nonce).toBe(url.searchParams.get('nonce'));
    expect(parsed.next).toBe('/account');
  });

  it('drops unsafe `next` (open-redirect defence)', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const r = await h.app.request(
      '/auth/google/start?next=https%3A%2F%2Fevil.com%2Fphish',
      { redirect: 'manual' },
    );
    expect(r.status).toBe(302);
    const state = new URL(r.headers.get('location')!).searchParams.get('state')!;
    const parsed = JSON.parse((await h.redis.get(`oauth:google:state:${state}`))!);
    expect(parsed.next).toBeUndefined();
  });

  it('404s when Google credentials are not configured', async () => {
    delete process.env.GOOGLE_OAUTH_CLIENT_ID;
    delete process.env.GOOGLE_OAUTH_CLIENT_SECRET;
    const { resetConfigForTest } = await import('../src/lib/config.js');
    resetConfigForTest();
    const h = await createTestHarness();
    const r = await h.app.request('/auth/google/start');
    expect(r.status).toBe(404);
  });
});

describe('GET /auth/google/callback — sign-in / sign-up branches', () => {
  it('Case C — sign-up: new sub, new email → creates human + records oauth+email, sets session', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);

    // Kick off /start to seed Redis state.
    const start = await h.app.request('/auth/google/start', { redirect: 'manual' });
    const startUrl = new URL(start.headers.get('location')!);
    const state = startUrl.searchParams.get('state')!;
    const nonce = startUrl.searchParams.get('nonce')!;

    const idToken = await google.mintIdToken({
      sub: 'google-sub-c',
      email: 'newuser@example.com',
      email_verified: true,
      nonce,
    });
    google.setNextTokenResponse(idToken);

    const r = await h.app.request(
      `/auth/google/callback?code=fake-code&state=${state}`,
      { redirect: 'manual' },
    );
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/account');
    expect(r.headers.get('set-cookie') ?? '').toMatch(/trust_sess=/);

    const human = await h.store.getHumanByEmail('newuser@example.com');
    expect(human).not.toBeNull();
    const vs = await h.store.listVerifications(human!.id);
    expect(vs.map((v) => `${v.method}:${v.provider}`).sort()).toEqual([
      'email:google-verified',
      'oauth:google',
    ]);
    const oauth = vs.find((v) => v.method === 'oauth')!;
    expect(oauth.external_subject).toBe('google-sub-c');
  });

  it('Case A — sign-in: returning sub, no session → logs in as the existing human', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const existing = await h.store.upsertHuman({ primary_email: 'returning@example.com' });
    await h.store.recordVerification(existing.id, 'oauth', 'google', 'google-sub-a');

    const start = await h.app.request('/auth/google/start', { redirect: 'manual' });
    const startUrl = new URL(start.headers.get('location')!);
    const state = startUrl.searchParams.get('state')!;
    const nonce = startUrl.searchParams.get('nonce')!;

    const idToken = await google.mintIdToken({
      sub: 'google-sub-a',
      email: 'returning@example.com',
      email_verified: true,
      nonce,
    });
    google.setNextTokenResponse(idToken);

    const r = await h.app.request(
      `/auth/google/callback?code=fake&state=${state}`,
      { redirect: 'manual' },
    );
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/account');
    // No second human created.
    const all = await h.store.getHumanByEmail('returning@example.com');
    expect(all!.id).toBe(existing.id);
  });

  it('Case B — link: logged-in human adds Google with matching email', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const human = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
    await h.store.recordVerification(human.id, 'email', 'magic-link');

    // Create a session cookie so /start picks up the linkingHumanId branch.
    const sessionRaw = await createBrowserSession(h, human.id);

    const start = await h.app.request('/auth/google/start', {
      headers: { cookie: `trust_sess=${sessionRaw}` },
      redirect: 'manual',
    });
    const startUrl = new URL(start.headers.get('location')!);
    const state = startUrl.searchParams.get('state')!;
    const nonce = startUrl.searchParams.get('nonce')!;
    const pending = JSON.parse((await h.redis.get(`oauth:google:state:${state}`))!);
    expect(pending.linkingHumanId).toBe(human.id);

    const idToken = await google.mintIdToken({
      sub: 'google-sub-b',
      email: 'alice@example.com',
      email_verified: true,
      nonce,
    });
    google.setNextTokenResponse(idToken);

    const r = await h.app.request(
      `/auth/google/callback?code=fake&state=${state}`,
      {
        headers: { cookie: `trust_sess=${sessionRaw}` },
        redirect: 'manual',
      },
    );
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/account');
    const vs = await h.store.listVerifications(human.id);
    expect(vs.some((v) => v.method === 'oauth' && v.external_subject === 'google-sub-b')).toBe(
      true,
    );
  });

  it('Case E — idempotent: signed-in human re-clicks Continue with Google → no-op redirect', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const human = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
    await h.store.recordVerification(human.id, 'oauth', 'google', 'google-sub-e');
    const sessionRaw = await createBrowserSession(h, human.id);

    const start = await h.app.request('/auth/google/start', {
      headers: { cookie: `trust_sess=${sessionRaw}` },
      redirect: 'manual',
    });
    const url = new URL(start.headers.get('location')!);
    const idToken = await google.mintIdToken({
      sub: 'google-sub-e',
      email: 'alice@example.com',
      email_verified: true,
      nonce: url.searchParams.get('nonce')!,
    });
    google.setNextTokenResponse(idToken);

    const r = await h.app.request(
      `/auth/google/callback?code=x&state=${url.searchParams.get('state')}`,
      {
        headers: { cookie: `trust_sess=${sessionRaw}` },
        redirect: 'manual',
      },
    );
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/account');
    // Still exactly one oauth verification — no duplication.
    const vs = await h.store.listVerifications(human.id);
    expect(vs.filter((v) => v.method === 'oauth' && v.provider === 'google')).toHaveLength(1);
  });

  it('Case D — hijack: signed-in human cannot claim a sub already linked to another human', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const other = await h.store.upsertHuman({ primary_email: 'owner@example.com' });
    await h.store.recordVerification(other.id, 'oauth', 'google', 'google-sub-d');

    const me = await h.store.upsertHuman({ primary_email: 'attacker@example.com' });
    const sessionRaw = await createBrowserSession(h, me.id);

    const start = await h.app.request('/auth/google/start', {
      headers: { cookie: `trust_sess=${sessionRaw}` },
      redirect: 'manual',
    });
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;
    const nonce = new URL(start.headers.get('location')!).searchParams.get('nonce')!;
    const idToken = await google.mintIdToken({
      sub: 'google-sub-d',
      email: 'owner@example.com',
      email_verified: true,
      nonce,
    });
    google.setNextTokenResponse(idToken);

    const r = await h.app.request(`/auth/google/callback?code=x&state=${state}`, {
      headers: { cookie: `trust_sess=${sessionRaw}` },
      redirect: 'manual',
    });
    expect(r.status).toBe(409);
    expect(await r.text()).toContain('already linked to a different');
    // attacker did NOT get linked.
    const vs = await h.store.listVerifications(me.id);
    expect(vs.some((v) => v.method === 'oauth')).toBe(false);
  });

  it('rejects when logged-in human links a Google account with a different email', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const human = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
    const sessionRaw = await createBrowserSession(h, human.id);

    const start = await h.app.request('/auth/google/start', {
      headers: { cookie: `trust_sess=${sessionRaw}` },
      redirect: 'manual',
    });
    const url = new URL(start.headers.get('location')!);
    const idToken = await google.mintIdToken({
      sub: 'google-sub-mismatch',
      email: 'wrong@example.com',
      email_verified: true,
      nonce: url.searchParams.get('nonce')!,
    });
    google.setNextTokenResponse(idToken);

    const r = await h.app.request(
      `/auth/google/callback?code=x&state=${url.searchParams.get('state')}`,
      {
        headers: { cookie: `trust_sess=${sessionRaw}` },
        redirect: 'manual',
      },
    );
    expect(r.status).toBe(400);
    // Apostrophe escapes to &#39; in the HTML; assert on a stable
    // surrounding substring instead.
    expect(await r.text()).toContain('match the email on this trust.afauth.org account');
    const vs = await h.store.listVerifications(human.id);
    expect(vs.some((v) => v.method === 'oauth')).toBe(false);
  });

  it('rejects when email_verified=false in the ID token', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);

    const start = await h.app.request('/auth/google/start', { redirect: 'manual' });
    const url = new URL(start.headers.get('location')!);
    const idToken = await google.mintIdToken({
      sub: 'google-sub-ev',
      email: 'unverified@example.com',
      email_verified: false,
      nonce: url.searchParams.get('nonce')!,
    });
    google.setNextTokenResponse(idToken);

    const r = await h.app.request(
      `/auth/google/callback?code=x&state=${url.searchParams.get('state')}`,
      { redirect: 'manual' },
    );
    expect(r.status).toBe(400);
    expect(await h.store.getHumanByEmail('unverified@example.com')).toBeNull();
  });

  it('rejects callback with mismatched state', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const r = await h.app.request('/auth/google/callback?code=x&state=never-issued', {
      redirect: 'manual',
    });
    expect(r.status).toBe(400);
  });

  it('rejects callback without code or state', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const r = await h.app.request('/auth/google/callback', { redirect: 'manual' });
    expect(r.status).toBe(400);
  });

  it('renders cancelled-flow recovery page when Google returns ?error=', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const r = await h.app.request('/auth/google/callback?error=access_denied', {
      redirect: 'manual',
    });
    expect(r.status).toBe(400);
    expect(await r.text()).toContain('cancelled');
  });

  it('state is single-use: a replayed callback fails the second time', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const start = await h.app.request('/auth/google/start', { redirect: 'manual' });
    const url = new URL(start.headers.get('location')!);
    const state = url.searchParams.get('state')!;
    const nonce = url.searchParams.get('nonce')!;
    const idToken = await google.mintIdToken({
      sub: 'google-sub-replay',
      email: 'replay@example.com',
      email_verified: true,
      nonce,
    });
    google.setNextTokenResponse(idToken);

    const first = await h.app.request(`/auth/google/callback?code=c&state=${state}`, {
      redirect: 'manual',
    });
    expect(first.status).toBe(302);

    const second = await h.app.request(`/auth/google/callback?code=c&state=${state}`, {
      redirect: 'manual',
    });
    expect(second.status).toBe(400);
  });

  it('rejects ID token whose nonce does not match the state', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const start = await h.app.request('/auth/google/start', { redirect: 'manual' });
    const state = new URL(start.headers.get('location')!).searchParams.get('state')!;

    const idToken = await google.mintIdToken({
      sub: 'google-sub-n',
      email: 'badnonce@example.com',
      email_verified: true,
      nonce: 'a-completely-different-nonce',
    });
    google.setNextTokenResponse(idToken);

    const r = await h.app.request(`/auth/google/callback?code=c&state=${state}`, {
      redirect: 'manual',
    });
    expect(r.status).toBe(400);
  });
});

describe('POST /auth/google/revoke', () => {
  it('revokes the oauth verification for the signed-in human', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const human = await h.store.upsertHuman({ primary_email: 'r@example.com' });
    await h.store.recordVerification(human.id, 'email', 'magic-link');
    await h.store.recordVerification(human.id, 'oauth', 'google', 'sub-r');
    const sessionRaw = await createBrowserSession(h, human.id);

    const r = await h.app.request('/auth/google/revoke', {
      method: 'POST',
      headers: { cookie: `trust_sess=${sessionRaw}` },
      redirect: 'manual',
    });
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/account');

    const vs = await h.store.listVerifications(human.id);
    expect(vs.some((v) => v.method === 'oauth')).toBe(false);
    // Email survives.
    expect(vs.some((v) => v.method === 'email')).toBe(true);
  });

  it('unauthenticated revoke bounces to /signin', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const r = await h.app.request('/auth/google/revoke', {
      method: 'POST',
      redirect: 'manual',
    });
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toContain('/signin');
  });
});

// ---- session helpers ------------------------------------------------

async function createBrowserSession(h: TestHarness, humanId: string): Promise<string> {
  const { generateToken, hashToken } = await import('../src/lib/tokens.js');
  const raw = generateToken();
  await h.store.createSession(humanId, hashToken(raw), new Date(Date.now() + 3600_000));
  return raw;
}
