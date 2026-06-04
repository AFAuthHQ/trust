import { describe, expect, it, beforeEach } from 'vitest';
import { createTestHarness, type TestHarness } from './helpers.js';
import { generateToken, hashToken } from '../src/lib/tokens.js';

/**
 * Revoking an agent binding is permanent — revokeBinding() only matches
 * `revoked_at IS NULL` and never clears the stamp, so a misclick can't be
 * undone. The /account page therefore gates the revoke <form> behind a
 * confirmation <dialog> (opened by /account-confirm.js) that names the
 * agent and spells out the implications. These tests pin the server-
 * rendered surface that script hooks onto, plus the no-JS fallback.
 */
describe('revoke confirmation modal (/account)', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  async function signedIn() {
    const human = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
    const raw = generateToken();
    const expires = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000);
    await h.store.createSession(human.id, hashToken(raw), expires);
    return { human, cookie: `trust_sess=${raw}` };
  }

  function linkAgent(
    human_id: string,
    opts: { agent_did: string; agent_label?: string },
  ) {
    return h.store.createBinding({
      human_id,
      agent_did: opts.agent_did,
      agent_label: opts.agent_label,
      agent_pubkey_b64: 'dGVzdC1wdWJrZXk',
      expires_at: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
    });
  }

  const getAccount = (cookie: string) =>
    h.app.request('/account', { headers: { cookie } });

  it('puts the agent identity on the revoke form so the modal can name it', async () => {
    const { human, cookie } = await signedIn();
    await linkAgent(human.id, {
      agent_did: 'did:key:z6MkRevokeTest',
      agent_label: 'Build Bot',
    });
    const body = await (await getAccount(cookie)).text();

    expect(body).toContain('data-revoke');
    expect(body).toContain('data-agent-did="did:key:z6MkRevokeTest"');
    expect(body).toContain('data-agent-label="Build Bot"');
    // The form still targets the real endpoint — that is the no-JS path.
    expect(body).toMatch(/action="\/account\/bindings\/[^"]+\/revoke"/);
  });

  it('renders the confirmation dialog + script when an active binding exists', async () => {
    const { human, cookie } = await signedIn();
    await linkAgent(human.id, { agent_did: 'did:key:z6MkRevokeTest' });
    const body = await (await getAccount(cookie)).text();

    expect(body).toContain('id="revoke-modal"');
    expect(body).toContain('Revoke this agent?');
    // The implications the human must see before confirming.
    expect(body).toMatch(/Takes effect within 15 minutes/);
    expect(body).toMatch(/stay valid at services until they\s+expire/);
    // Permanence is scoped to the link/token (which can't be reactivated),
    // not an absolute "can't be undone" — the agent can be re-linked anew.
    expect(body).toContain("can't be reactivated");
    expect(body).not.toContain("can't be undone");
    expect(body).toMatch(/re-link it/);
    expect(body).toContain('src="/account-confirm.js"');
  });

  it('omits the dialog + script when there are no active bindings', async () => {
    const { cookie } = await signedIn();
    const body = await (await getAccount(cookie)).text();

    expect(body).not.toContain('id="revoke-modal"');
    // Match the <script> tag, not the bare path — the latter also
    // appears in a CSS comment that renders on every page.
    expect(body).not.toContain('src="/account-confirm.js"');
  });

  it('omits the dialog once the only binding is revoked', async () => {
    const { human, cookie } = await signedIn();
    const b = await linkAgent(human.id, { agent_did: 'did:key:z6MkRevokeTest' });
    await h.store.revokeBinding(b.id, human.id);
    const body = await (await getAccount(cookie)).text();

    // No active binding → nothing to revoke → no modal, no script, no form.
    expect(body).not.toContain('id="revoke-modal"');
    expect(body).not.toContain('src="/account-confirm.js"');
    expect(body).not.toContain('data-revoke');
    // The revoked agent is still listed (with a "revoked" pill).
    expect(body).toContain('did:key:z6MkRevokeTest');
  });

  it('serves /account-confirm.js same-origin, executable, gating the submit', async () => {
    const r = await h.app.request('/account-confirm.js');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type') ?? '').toMatch(/javascript/);
    const js = await r.text();
    // Grep, not eval: it hooks the revoke form, opens the dialog, and
    // blocks the default submit until the human confirms.
    expect(js).toMatch(/data-revoke/);
    expect(js).toMatch(/showModal/);
    expect(js).toMatch(/preventDefault/);
  });

  it('regression: POST /account/bindings/:id/revoke still revokes (no-JS path)', async () => {
    const { human, cookie } = await signedIn();
    const b = await linkAgent(human.id, { agent_did: 'did:key:z6MkRevokeTest' });
    const r = await h.app.request(`/account/bindings/${b.id}/revoke`, {
      method: 'POST',
      headers: { cookie, 'sec-fetch-site': 'same-origin' },
    });
    expect(r.status).toBe(302);
    expect(r.headers.get('location')).toBe('/account');
    const after = await h.store.listBindingsByHuman(human.id);
    expect(after.find((x) => x.id === b.id)?.revoked_at).toBeTruthy();
  });
});
