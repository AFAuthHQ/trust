import { describe, expect, it, beforeEach } from 'vitest';
import {
  createAgentKeypair,
  createTestHarness,
  postJson,
  postMint,
  type TestHarness,
} from './helpers.js';
import { confirmLinkRequest } from '../src/lib/link-confirm.js';
import { generateToken, hashToken } from '../src/lib/tokens.js';

/**
 * Connected-services ledger + per-service suspension (core.md §10.3.1 / §8.5).
 *
 * The attestor records each (agent DID, service) it mints for; the owner can
 * revoke minting for one pair, which the §3.1 keyless mint then refuses with
 * `service_suspended` — leaving the binding and every OTHER service intact.
 * Recording happens on a successful mint, so a brand-new pair is never
 * spuriously suspended.
 */
describe('connected-services ledger + per-service suspension', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
    // ioredis-mock shares one store across instances — flush so a prior
    // test's (keyid, nonce) replay entries don't leak.
    await h.redis.flushall();
  });

  type Keypair = Awaited<ReturnType<typeof createAgentKeypair>>;

  const SVC = 'did:web:svc.example';
  const code = async (r: Response) =>
    ((await r.json()) as { error: { code: string } }).error.code;

  /**
   * Link an agent to a (new) human AND open a dashboard session for that
   * human, so one test can mint (agent side, signed) and revoke via /account
   * (owner side, session) against the same identity.
   */
  async function setup(
    opts: { email?: string } = {},
  ): Promise<{ kp: Keypair; human: { id: string }; cookie: string }> {
    const kp = await createAgentKeypair();
    const startResp = await postJson(h.app, '/v1/link/start', {
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
    });
    const { req_id } = (await startResp.json()) as { req_id: string };
    const human = await h.store.upsertHuman({
      primary_email: opts.email ?? 'alice@example.com',
    });
    await h.store.recordVerification(human.id, 'email', 'magic-link');
    await confirmLinkRequest({ store: h.store, redis: h.redis, human, reqId: req_id });
    const raw = generateToken();
    await h.store.createSession(
      human.id,
      hashToken(raw),
      new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    );
    return { kp, human, cookie: `trust_sess=${raw}` };
  }

  // ---- ledger ----

  it('records a (agent, service) signup row on the first mint', async () => {
    const { kp, human } = await setup();
    expect((await postMint(h.app, kp.privateKey, kp.did, SVC)).status).toBe(200);

    const rows = await h.store.listServiceSignupsByHuman(human.id);
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      agent_did: kp.did,
      service_did: SVC,
      revoked_at: null,
    });
  });

  it('dedupes repeat mints for the same pair into a single row', async () => {
    const { kp, human } = await setup();
    await postMint(h.app, kp.privateKey, kp.did, SVC);
    await postMint(h.app, kp.privateKey, kp.did, SVC);
    expect(await h.store.listServiceSignupsByHuman(human.id)).toHaveLength(1);
  });

  it('a brand-new pair is never spuriously suspended (first mint proceeds)', async () => {
    const { kp } = await setup();
    expect((await postMint(h.app, kp.privateKey, kp.did, SVC)).status).toBe(200);
  });

  // ---- suspension on the mint path ----

  it('refuses to mint a revoked pair with 403 service_suspended', async () => {
    const { kp, human } = await setup();
    await postMint(h.app, kp.privateKey, kp.did, SVC); // creates the row
    const [row] = await h.store.listServiceSignupsByHuman(human.id);
    await h.store.setServiceSignupRevoked(row!.id, human.id, true);

    const r = await postMint(h.app, kp.privateKey, kp.did, SVC);
    expect(r.status).toBe(403);
    expect(await code(r)).toBe('service_suspended');
  });

  it('restore re-enables minting for the pair', async () => {
    const { kp, human } = await setup();
    await postMint(h.app, kp.privateKey, kp.did, SVC);
    const [row] = await h.store.listServiceSignupsByHuman(human.id);

    await h.store.setServiceSignupRevoked(row!.id, human.id, true);
    expect((await postMint(h.app, kp.privateKey, kp.did, SVC)).status).toBe(403);

    await h.store.setServiceSignupRevoked(row!.id, human.id, false);
    expect((await postMint(h.app, kp.privateKey, kp.did, SVC)).status).toBe(200);
  });

  it('suspension is per-service: revoking one aud leaves others mintable', async () => {
    const { kp, human } = await setup();
    const OTHER = 'did:web:other.example';
    await postMint(h.app, kp.privateKey, kp.did, SVC);
    await postMint(h.app, kp.privateKey, kp.did, OTHER);

    const svcRow = (await h.store.listServiceSignupsByHuman(human.id)).find(
      (r) => r.service_did === SVC,
    )!;
    await h.store.setServiceSignupRevoked(svcRow.id, human.id, true);

    expect((await postMint(h.app, kp.privateKey, kp.did, SVC)).status).toBe(403);
    expect((await postMint(h.app, kp.privateKey, kp.did, OTHER)).status).toBe(200);
  });

  it('setServiceSignupRevoked is scoped to the owner (a different human cannot toggle)', async () => {
    const { kp, human } = await setup();
    await postMint(h.app, kp.privateKey, kp.did, SVC);
    const [row] = await h.store.listServiceSignupsByHuman(human.id);
    const other = await h.store.upsertHuman({ primary_email: 'mallory@example.com' });

    expect(await h.store.setServiceSignupRevoked(row!.id, other.id, true)).toBeNull();
    // The pair is untouched — still mintable.
    expect((await postMint(h.app, kp.privateKey, kp.did, SVC)).status).toBe(200);
  });

  // ---- dashboard (/account) ----

  it('renders the Signups section with the service and a per-row revoke form', async () => {
    const { kp, cookie } = await setup();
    await postMint(h.app, kp.privateKey, kp.did, SVC);

    const body = await (await h.app.request('/account', { headers: { cookie } })).text();
    expect(body).toContain('Signups');
    expect(body).toContain(SVC);
    expect(body).toContain('/account/signups/'); // the per-row revoke form action
  });

  it('revoking via the dashboard route suspends the pair end-to-end', async () => {
    const { kp, human, cookie } = await setup();
    await postMint(h.app, kp.privateKey, kp.did, SVC);
    const [row] = await h.store.listServiceSignupsByHuman(human.id);

    const r = await h.app.request(`/account/signups/${row!.id}/revoke`, {
      method: 'POST',
      headers: { 'sec-fetch-site': 'same-origin', cookie },
    });
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/account');

    // Mint is now refused…
    expect((await postMint(h.app, kp.privateKey, kp.did, SVC)).status).toBe(403);
    // …and the dashboard shows the revoked state + a restore control.
    const body = await (await h.app.request('/account', { headers: { cookie } })).text();
    expect(body).toContain('revoked');
    expect(body).toContain('Allow again');
  });

  it('the dashboard revoke route requires a session (redirects to /signin)', async () => {
    const { kp, human } = await setup();
    await postMint(h.app, kp.privateKey, kp.did, SVC);
    const [row] = await h.store.listServiceSignupsByHuman(human.id);

    const r = await h.app.request(`/account/signups/${row!.id}/revoke`, {
      method: 'POST',
      headers: { 'sec-fetch-site': 'same-origin' },
    });
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toContain('/signin');
    // Nothing changed — still mintable.
    expect((await postMint(h.app, kp.privateKey, kp.did, SVC)).status).toBe(200);
  });
});
