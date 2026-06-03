import { describe, expect, it, beforeEach } from 'vitest';
import {
  createAgentKeypair,
  createTestHarness,
  postJson,
  type TestHarness,
} from './helpers.js';
import { generateToken, hashToken } from '../src/lib/tokens.js';

/**
 * Revoking a binding is permanent for that binding, but the agent DID can
 * be re-linked (a fresh binding). If the owner is re-linking a DID they
 * previously revoked — e.g. a key they pulled because it leaked — the
 * /link page warns that re-linking re-enables the same key. Scoped to the
 * current human so one owner's revocation history isn't shown to another.
 */
describe('re-link warning on /link (previously revoked agent)', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  async function signedIn(email = 'alice@example.com') {
    const human = await h.store.upsertHuman({ primary_email: email });
    const raw = generateToken();
    await h.store.createSession(
      human.id,
      hashToken(raw),
      new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    );
    return { human, cookie: `trust_sess=${raw}` };
  }

  async function startLinkReqPath(kp: Awaited<ReturnType<typeof createAgentKeypair>>) {
    const r = await postJson(h.app, '/v1/link/start', {
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
      agent_label: 'Build Bot',
    });
    expect(r.status).toBe(200);
    const body = (await r.json()) as { link_url: string };
    const u = new URL(body.link_url);
    return u.pathname + u.search; // "/link?req=<jwt>"
  }

  async function createRevokedBinding(
    human_id: string,
    kp: Awaited<ReturnType<typeof createAgentKeypair>>,
  ) {
    const b = await h.store.createBinding({
      human_id,
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
      binding_token_hash: hashToken(generateToken()),
      expires_at: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    });
    await h.store.revokeBinding(b.id, human_id);
  }

  const getLink = (path: string, cookie: string) =>
    h.app.request(path, { headers: { cookie } });

  it('warns (with timestamp) when this human previously revoked the DID', async () => {
    const { human, cookie } = await signedIn();
    const kp = await createAgentKeypair();
    await createRevokedBinding(human.id, kp);

    const path = await startLinkReqPath(kp);
    const body = await (await getLink(path, cookie)).text();

    expect(body).toMatch(/This agent was revoked\s+on/);
    expect(body).toMatch(/re-enables it/);
    // "2026-06-03 08:52:01 UTC" — formatted revoked_at.
    expect(body).toMatch(/\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/);
  });

  it('no warning for a DID this human never revoked', async () => {
    const { cookie } = await signedIn();
    const kp = await createAgentKeypair();

    const path = await startLinkReqPath(kp);
    const body = await (await getLink(path, cookie)).text();

    expect(body).not.toContain('was revoked on');
  });

  it('no warning when an active binding already exists (refresh, not a revoked re-link)', async () => {
    const { human, cookie } = await signedIn();
    const kp = await createAgentKeypair();
    // Active (un-revoked) binding for the same DID.
    await h.store.createBinding({
      human_id: human.id,
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
      binding_token_hash: hashToken(generateToken()),
      expires_at: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    });

    const path = await startLinkReqPath(kp);
    const body = await (await getLink(path, cookie)).text();

    expect(body).not.toContain('was revoked on');
  });

  it('no warning to a different human who never revoked it (no cross-human disclosure)', async () => {
    // Alice revokes the DID...
    const alice = await signedIn('alice@example.com');
    const kp = await createAgentKeypair();
    await createRevokedBinding(alice.human.id, kp);

    // ...Bob, signed in separately, opens a link for the same DID.
    const bob = await signedIn('bob@example.com');
    const path = await startLinkReqPath(kp);
    const body = await (await getLink(path, bob.cookie)).text();

    expect(body).not.toContain('was revoked on');
  });
});
