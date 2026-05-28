import { describe, expect, it, beforeEach } from 'vitest';
import {
  createAgentKeypair,
  createTestHarness,
  postJson,
  signEd25519,
  type TestHarness,
} from './helpers.js';
import { confirmLinkRequest } from '../src/lib/link-confirm.js';

describe('link flow — start → confirm → poll', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  async function startLink(agentDidOverride?: string) {
    const kp = await createAgentKeypair();
    const r = await postJson(h.app, '/v1/link/start', {
      agent_did: agentDidOverride ?? kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
      agent_label: 'test-agent',
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as {
      req_id: string;
      link_url: string;
      poll_url: string;
      expires_in: number;
    };
    return { kp, body };
  }

  it('start returns a deep link with the embedded req JWT', async () => {
    const { body } = await startLink();
    expect(body.req_id).toMatch(/^[0-9a-f-]{36}$/);
    expect(body.link_url).toContain('/link?req=');
    expect(body.poll_url).toContain('/v1/link/poll');
    expect(body.expires_in).toBe(1800);
  });

  it('poll on a pending request returns state=pending with phase=awaiting_signin', async () => {
    const { kp, body } = await startLink();
    const sig = await signEd25519(
      kp.privateKey,
      new TextEncoder().encode(body.req_id),
    );
    const r = await postJson(h.app, '/v1/link/poll', {
      req_id: body.req_id,
      sig_b64: sig,
    });
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ state: 'pending', phase: 'awaiting_signin' });
  });

  it('phase flips to awaiting_confirm after the /link page is loaded', async () => {
    const { kp, body } = await startLink();

    // Simulate the browser opening the deep link. The page handler
    // sets the per-request viewed marker we'll observe via /v1/link/poll.
    const url = new URL(body.link_url);
    const pageRes = await h.app.fetch(
      new Request(`http://localhost${url.pathname}${url.search}`),
    );
    expect(pageRes.status).toBe(200);

    const sig = await signEd25519(
      kp.privateKey,
      new TextEncoder().encode(body.req_id),
    );
    const r = await postJson(h.app, '/v1/link/poll', {
      req_id: body.req_id,
      sig_b64: sig,
    });
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual({ state: 'pending', phase: 'awaiting_confirm' });
  });

  it('poll without a valid agent signature is 401', async () => {
    const { body } = await startLink();
    const r = await postJson(h.app, '/v1/link/poll', {
      req_id: body.req_id,
      sig_b64: 'AAAA',
    });
    expect(r.status).toBe(401);
  });

  it('full flow: confirm → poll → binding token issued exactly once', async () => {
    const { kp, body } = await startLink();

    // Simulate the human confirming via the dashboard.
    const human = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
    await h.store.recordVerification(human.id, 'email', 'magic-link');
    const confirmed = await confirmLinkRequest({
      store: h.store,
      redis: h.redis,
      human,
      reqId: body.req_id,
    });
    expect(confirmed.binding_id).toBeTruthy();
    expect(confirmed.binding_token).toBeTruthy();

    // Agent polls and pops the binding token.
    const sig = await signEd25519(
      kp.privateKey,
      new TextEncoder().encode(body.req_id),
    );
    const r = await postJson(h.app, '/v1/link/poll', {
      req_id: body.req_id,
      sig_b64: sig,
    });
    expect(r.status).toBe(200);
    const polled = (await r.json()) as {
      state: 'confirmed';
      binding_id: string;
      binding_token: string;
    };
    expect(polled.state).toBe('confirmed');
    expect(polled.binding_id).toBe(confirmed.binding_id);
    expect(polled.binding_token).toBe(confirmed.binding_token);

    // A second poll should fail — binding_token is delivered once.
    const r2 = await postJson(h.app, '/v1/link/poll', {
      req_id: body.req_id,
      sig_b64: sig,
    });
    expect(r2.status).toBe(410);
  });

  it('rejects loopback callbacks that are not 127.0.0.1/localhost', async () => {
    const kp = await createAgentKeypair();
    const r = await postJson(h.app, '/v1/link/start', {
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
      callback_url: 'https://attacker.example/done',
    });
    expect(r.status).toBe(400);
  });

  it('accepts a loopback callback', async () => {
    const kp = await createAgentKeypair();
    const r = await postJson(h.app, '/v1/link/start', {
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
      callback_url: 'http://127.0.0.1:53219/done',
    });
    expect(r.status).toBe(200);
  });

  it('/v1/link/confirm without a session is 401', async () => {
    const { body } = await startLink();
    const r = await postJson(h.app, '/v1/link/confirm', { req_id: body.req_id });
    expect(r.status).toBe(401);
  });
});

describe('AFAP-0006 §10.5 — one active human binding per agent DID', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  async function linkAs(human: { id: string; primary_email: string }, agentDid: string, pubKeyB64: string) {
    const lr = await h.store.createLinkRequest({
      agent_did: agentDid,
      agent_pubkey_b64: pubKeyB64,
      expires_at: new Date(Date.now() + 30 * 60_000),
    });
    return confirmLinkRequest({
      store: h.store,
      redis: h.redis,
      human: { id: human.id, primary_email: human.primary_email, created_at: new Date(), disabled_at: null },
      reqId: lr.id,
    });
  }

  it('rejects a second binding for the same agent_did from a different human', async () => {
    const kp = await createAgentKeypair();
    const alice = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
    const bob = await h.store.upsertHuman({ primary_email: 'bob@example.com' });

    const aliceConfirm = await linkAs(alice, kp.did, kp.publicKeyB64);
    expect(aliceConfirm.binding_id).toBeTruthy();

    await expect(linkAs(bob, kp.did, kp.publicKeyB64)).rejects.toMatchObject({
      code: 'agent_already_bound',
      status: 409,
    });
  });

  it('rejection message does NOT disclose the existing owner', async () => {
    const kp = await createAgentKeypair();
    const alice = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
    const bob = await h.store.upsertHuman({ primary_email: 'bob@example.com' });
    await linkAs(alice, kp.did, kp.publicKeyB64);

    try {
      await linkAs(bob, kp.did, kp.publicKeyB64);
      throw new Error('expected agentAlreadyBound');
    } catch (err) {
      const msg = (err as { message: string }).message;
      expect(msg).not.toMatch(/alice/i);
      expect(msg).not.toMatch(/example\.com/i);
      expect(msg).not.toMatch(alice.id);
    }
  });

  it('allows the same human to re-link the same agent_did (refresh binding token)', async () => {
    const kp = await createAgentKeypair();
    const alice = await h.store.upsertHuman({ primary_email: 'alice@example.com' });

    const first = await linkAs(alice, kp.did, kp.publicKeyB64);
    const second = await linkAs(alice, kp.did, kp.publicKeyB64);

    expect(second.binding_id).toBe(first.binding_id); // same row, refreshed
    expect(second.binding_token).not.toBe(first.binding_token); // new token
  });

  it('allows a different human to bind after the existing owner revokes', async () => {
    const kp = await createAgentKeypair();
    const alice = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
    const bob = await h.store.upsertHuman({ primary_email: 'bob@example.com' });

    const aliceConfirm = await linkAs(alice, kp.did, kp.publicKeyB64);
    await h.store.revokeBinding(aliceConfirm.binding_id, alice.id);

    const bobConfirm = await linkAs(bob, kp.did, kp.publicKeyB64);
    expect(bobConfirm.binding_id).toBeTruthy();
    expect(bobConfirm.binding_id).not.toBe(aliceConfirm.binding_id);
  });

  it('different humans can bind different agent_dids without conflict', async () => {
    const kp1 = await createAgentKeypair();
    const kp2 = await createAgentKeypair();
    const alice = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
    const bob = await h.store.upsertHuman({ primary_email: 'bob@example.com' });

    const a = await linkAs(alice, kp1.did, kp1.publicKeyB64);
    const b = await linkAs(bob, kp2.did, kp2.publicKeyB64);

    expect(a.binding_id).toBeTruthy();
    expect(b.binding_id).toBeTruthy();
    expect(a.binding_id).not.toBe(b.binding_id);
  });

  it('findActiveBindingByAgentDid returns null for revoked bindings', async () => {
    const kp = await createAgentKeypair();
    const alice = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
    const confirm = await linkAs(alice, kp.did, kp.publicKeyB64);

    const before = await h.store.findActiveBindingByAgentDid(kp.did);
    expect(before?.id).toBe(confirm.binding_id);

    await h.store.revokeBinding(confirm.binding_id, alice.id);

    const after = await h.store.findActiveBindingByAgentDid(kp.did);
    expect(after).toBeNull();
  });
});
