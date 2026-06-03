import { beforeEach, describe, expect, it } from 'vitest';
import {
  createAgentKeypair,
  createTestHarness,
  postJson,
  postMint,
  type TestHarness,
} from './helpers.js';
import { confirmLinkRequest } from '../src/lib/link-confirm.js';

const ADMIN = 'test-admin-secret-16';

describe('POST /admin/keys/rotate — graceful rotation', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  it('requires the admin bearer', async () => {
    const r = await postJson(h.app, '/admin/keys/rotate', {});
    expect(r.status).toBe(401);
  });

  it('rejects the wrong admin bearer', async () => {
    const r = await postJson(
      h.app,
      '/admin/keys/rotate',
      {},
      { headers: { authorization: 'Bearer not-the-secret' } },
    );
    expect(r.status).toBe(401);
  });

  it('mints a new kid with default 900s delay so JWKS can refresh first', async () => {
    const before = await h.vault.list();
    expect(before.length).toBe(1); // bootstrap kid from createTestHarness

    const r = await postJson(
      h.app,
      '/admin/keys/rotate',
      {},
      { headers: { authorization: `Bearer ${ADMIN}` } },
    );
    expect(r.status).toBe(200);
    const body = (await r.json()) as {
      kid: string;
      delay_seconds: number;
      active_from: string;
    };
    expect(body.kid).toBeTruthy();
    expect(body.delay_seconds).toBe(900);
    expect(new Date(body.active_from).getTime() - Date.now()).toBeGreaterThan(800_000);

    // JWKS publishes both kids immediately — the new one is included
    // even before activeFrom so consumer caches can refresh ahead.
    const jwks = await h.app.request('/.well-known/jwks.json');
    const jwksBody = (await jwks.json()) as { keys: Array<{ kid: string }> };
    expect(jwksBody.keys.length).toBe(2);

    // But getActive() still returns the old kid until activeFrom passes.
    const active = await h.vault.getActive();
    expect(active.kid).toBe(before[0]!.kid);
    expect(active.kid).not.toBe(body.kid);
  });

  it('honours an explicit zero-delay rotation when the operator opts in', async () => {
    const before = await h.vault.getActive();

    const r = await postJson(
      h.app,
      '/admin/keys/rotate',
      { delaySeconds: 0 },
      { headers: { authorization: `Bearer ${ADMIN}` } },
    );
    expect(r.status).toBe(200);
    const body = (await r.json()) as { kid: string };

    const active = await h.vault.getActive();
    expect(active.kid).toBe(body.kid);
    expect(active.kid).not.toBe(before.kid);
  });
});

describe('POST /admin/keys/retire — removes from JWKS', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  it('retires a kid (JWKS drops it, getActive picks the surviving one)', async () => {
    // Add a second kid so we can retire the first without leaving the
    // service unable to sign.
    const rot = await postJson(
      h.app,
      '/admin/keys/rotate',
      { delaySeconds: 0 },
      { headers: { authorization: `Bearer ${ADMIN}` } },
    );
    const newKid = ((await rot.json()) as { kid: string }).kid;

    const all = await h.vault.list();
    const oldKid = all.find((k) => k.kid !== newKid)!.kid;

    const ret = await postJson(
      h.app,
      '/admin/keys/retire',
      { kid: oldKid },
      { headers: { authorization: `Bearer ${ADMIN}` } },
    );
    expect(ret.status).toBe(200);

    const jwks = await h.app.request('/.well-known/jwks.json');
    const jwksBody = (await jwks.json()) as { keys: Array<{ kid: string }> };
    expect(jwksBody.keys.map((k) => k.kid)).toEqual([newKid]);
  });

  it('does not throw when retiring an already-retired kid (idempotent)', async () => {
    const r1 = await postJson(
      h.app,
      '/admin/keys/rotate',
      { delaySeconds: 0 },
      { headers: { authorization: `Bearer ${ADMIN}` } },
    );
    const kid = ((await r1.json()) as { kid: string }).kid;

    const r2 = await postJson(
      h.app,
      '/admin/keys/retire',
      { kid: 'tk-does-not-exist' },
      { headers: { authorization: `Bearer ${ADMIN}` } },
    );
    expect(r2.status).toBe(200);

    // Retiring a real kid twice is fine.
    const a = await postJson(
      h.app,
      '/admin/keys/retire',
      { kid },
      { headers: { authorization: `Bearer ${ADMIN}` } },
    );
    const b = await postJson(
      h.app,
      '/admin/keys/retire',
      { kid },
      { headers: { authorization: `Bearer ${ADMIN}` } },
    );
    expect(a.status).toBe(200);
    expect(b.status).toBe(200);
  });
});

describe('GET /admin/keys — lists current state', () => {
  it('reports active and pending kids', async () => {
    const h = await createTestHarness();
    await postJson(
      h.app,
      '/admin/keys/rotate',
      {},
      { headers: { authorization: `Bearer ${ADMIN}` } },
    );
    const r = await h.app.request('/admin/keys', {
      headers: { authorization: `Bearer ${ADMIN}` },
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as {
      keys: Array<{ kid: string; active: boolean; retired: boolean }>;
    };
    expect(body.keys.length).toBe(2);
    expect(body.keys.filter((k) => k.active).length).toBe(1);
    expect(body.keys.filter((k) => !k.active && !k.retired).length).toBe(1);
  });
});

describe('rotation grace period — tokens minted across rotation remain verifiable', () => {
  it('an old-kid token still verifies after a new kid is published', async () => {
    const h = await createTestHarness();

    // Set up an agent + link + verification so we can mint a real token.
    const kp = await createAgentKeypair();
    const startResp = await postJson(h.app, '/v1/link/start', {
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
    });
    const { req_id } = (await startResp.json()) as { req_id: string };
    const human = await h.store.upsertHuman({ primary_email: 'rot@example.com' });
    await h.store.recordVerification(human.id, 'email', 'magic-link');
    const confirmed = await confirmLinkRequest({
      store: h.store,
      redis: h.redis,
      human,
      reqId: req_id,
    });

    // Mint a token under the original kid (keyless: signed with kp).
    const t1 = await postMint(h.app, kp.privateKey, kp.did, 'did:web:svc.example');
    const jwt1 = ((await t1.json()) as { jwt: string }).jwt;
    const kid1 = parseKid(jwt1);

    // Rotate (default 900s grace — old kid stays active for signing).
    await postJson(
      h.app,
      '/admin/keys/rotate',
      {},
      { headers: { authorization: `Bearer ${ADMIN}` } },
    );

    // The old kid is still the active signer (900s delay), and the
    // JWKS now publishes both. New tokens still go under the old kid.
    const t2 = await postMint(h.app, kp.privateKey, kp.did, 'did:web:svc.example');
    const jwt2 = ((await t2.json()) as { jwt: string }).jwt;
    expect(parseKid(jwt2)).toBe(kid1);
  });
});

function parseKid(jwt: string): string {
  const [headerB64] = jwt.split('.');
  const header = JSON.parse(Buffer.from(headerB64!, 'base64url').toString());
  return header.kid as string;
}
