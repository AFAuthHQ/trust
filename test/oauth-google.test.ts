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

  it('Case C with prior magic-link verification: does NOT add a redundant email row', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    // Pre-existing human who already used magic-link.
    const existing = await h.store.upsertHuman({ primary_email: 'priormagic@example.com' });
    await h.store.recordVerification(existing.id, 'email', 'magic-link');

    const start = await h.app.request('/auth/google/start', { redirect: 'manual' });
    const url = new URL(start.headers.get('location')!);
    const idToken = await google.mintIdToken({
      sub: 'google-sub-c-prior',
      email: 'priormagic@example.com',
      email_verified: true,
      nonce: url.searchParams.get('nonce')!,
    });
    google.setNextTokenResponse(idToken);

    const r = await h.app.request(
      `/auth/google/callback?code=fake&state=${url.searchParams.get('state')}`,
      { redirect: 'manual' },
    );
    expect(r.status).toBe(302);

    const vs = await h.store.listVerifications(existing.id);
    // Exactly two rows: the prior magic-link AND the new oauth. NOT a
    // second email row.
    expect(vs.filter((v) => v.method === 'email')).toHaveLength(1);
    expect(vs.find((v) => v.method === 'email')!.provider).toBe('magic-link');
    expect(vs.filter((v) => v.method === 'oauth')).toHaveLength(1);
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
    // A successful Google auth always leaves a fresh session cookie —
    // even when the human was already signed in (linking). Keeps the
    // §7.5 freshness floor satisfiable by re-authenticating.
    expect(r.headers.get('set-cookie') ?? '').toMatch(/trust_sess=/);
    const vs = await h.store.listVerifications(human.id);
    expect(vs.some((v) => v.method === 'oauth' && v.external_subject === 'google-sub-b')).toBe(
      true,
    );
  });

  it('Case E — re-auth: signed-in human re-clicks Continue with Google → refreshes session', async () => {
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
    // Re-authenticating refreshes the session (new cookie) so a stale
    // session can become fresh again — see the resume-loop regression
    // below. Not a no-op.
    expect(r.headers.get('set-cookie') ?? '').toMatch(/trust_sess=/);
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

describe('session freshness on re-auth (paused-account resume loop)', () => {
  /**
   * Regression for the "resume keeps bouncing me to login" loop.
   *
   * /account/resume enforces a §7.5 freshness floor: a session older
   * than 300s must re-authenticate before it can un-pause the account.
   * The bounce keeps the existing (stale) session cookie, so when the
   * user re-authenticates with Google, /start enters linking mode and
   * the callback lands in Case E (sub already linked to this human).
   *
   * Case E used to be a no-op that only refreshed verified_at — it did
   * NOT mint a new session. So the session stayed stale, resume bounced
   * again, and the user looped forever, unable to resume. The fix makes
   * every successful Google auth refresh the session.
   */
  it('Google re-auth refreshes a stale session so a paused account can resume (no loop)', async () => {
    const google = await makeFakeGoogle();
    const h = await freshHarness(google);
    const human = await h.store.upsertHuman({ primary_email: 'looper@example.com' });
    await h.store.recordVerification(human.id, 'oauth', 'google', 'google-sub-loop');
    await h.store.setHumanPaused(human.id, true);

    // A stale session (> 300s old) — the kind that fails the resume
    // freshness floor. MemoryStore hands back the live object, so
    // backdating created_at sticks.
    const { generateToken, hashToken } = await import('../src/lib/tokens.js');
    const staleRaw = generateToken();
    const stale = await h.store.createSession(
      human.id,
      hashToken(staleRaw),
      new Date(Date.now() + 3600_000),
    );
    stale.created_at = new Date(Date.now() - 10 * 60 * 1000);

    // Precondition: resuming with the stale session bounces to /signin
    // and the account stays paused.
    const bounced = await h.app.request('/account/resume', {
      method: 'POST',
      headers: { cookie: `trust_sess=${staleRaw}` },
      redirect: 'manual',
    });
    expect(bounced.status).toBe(302);
    expect(bounced.headers.get('location')).toContain('/signin');
    expect((await h.store.getHumanById(human.id))?.paused_at).toBeTruthy();

    // User clicks "Continue with Google". The stale cookie rides along,
    // so /start records linkingHumanId and the callback hits Case E.
    const start = await h.app.request('/auth/google/start?next=%2Faccount', {
      headers: { cookie: `trust_sess=${staleRaw}` },
      redirect: 'manual',
    });
    const url = new URL(start.headers.get('location')!);
    const idToken = await google.mintIdToken({
      sub: 'google-sub-loop',
      email: 'looper@example.com',
      email_verified: true,
      nonce: url.searchParams.get('nonce')!,
    });
    google.setNextTokenResponse(idToken);

    const cb = await h.app.request(
      `/auth/google/callback?code=x&state=${url.searchParams.get('state')}`,
      { headers: { cookie: `trust_sess=${staleRaw}` }, redirect: 'manual' },
    );
    expect(cb.status).toBe(302);
    expect(cb.headers.get('location')).toBe('/account');

    // The fix: the callback mints a FRESH session cookie distinct from
    // the stale one.
    const setCookie = cb.headers.get('set-cookie') ?? '';
    expect(setCookie).toMatch(/trust_sess=/);
    const freshCookie = setCookie.split(';')[0]!; // "trust_sess=<token>"
    expect(freshCookie).not.toBe(`trust_sess=${staleRaw}`);

    // With the refreshed session, resume now succeeds — loop broken.
    const resumed = await h.app.request('/account/resume', {
      method: 'POST',
      headers: { cookie: freshCookie },
      redirect: 'manual',
    });
    expect(resumed.status).toBe(302);
    expect(resumed.headers.get('location')).toBe('/account');
    expect((await h.store.getHumanById(human.id))?.paused_at).toBeNull();
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
