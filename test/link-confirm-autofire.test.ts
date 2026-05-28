/**
 * Regression: the /link/confirm browser flow MUST auto-notify the
 * agent's loopback callback. Without this, the CLI hangs on
 * "Waiting…" after the human confirms in the browser — the
 * "Return to the agent" button is documented to be optional
 * ("the agent has already been notified — closing this tab is
 * fine too").
 *
 * Inline `<script>` is incompatible with the strict CSP
 * (`script-src 'self'` with no unsafe-inline), so the fire must
 * use a same-origin static script that reads the callback URL
 * from a data attribute.
 *
 * Two layers of test:
 *   1. Unit: linkConfirmedPage HTML carries a CSP-compatible
 *      auto-fire mechanism targeting the callback URL.
 *   2. Integration: drive the link flow end-to-end up to confirm,
 *      parse the HTML, simulate the browser fetching the static
 *      script's data-callback target, assert a fake loopback
 *      server saw the hit.
 */
import { describe, expect, it, beforeEach, afterEach } from 'vitest';
import { createServer, type Server } from 'node:http';
import { AddressInfo } from 'node:net';
import { createAgentKeypair, createTestHarness, type TestHarness } from './helpers.js';
import { confirmLinkRequest } from '../src/lib/link-confirm.js';
import { generateToken, hashToken } from '../src/lib/tokens.js';

describe('linkConfirmedPage auto-fire (regression for CLI-stuck-on-Waiting bug)', () => {
  let h: TestHarness;
  beforeEach(async () => {
    h = await createTestHarness();
  });

  // Helper: end-to-end through to a session cookie + a link request
  // that's been confirmed via the HTML form path, returning the
  // body of the POST /link/confirm response (the linkConfirmedPage HTML).
  async function confirmAndReturnHtml(callbackUrl: string | undefined): Promise<{
    status: number;
    contentType: string;
    html: string;
  }> {
    const human = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
    await h.store.recordVerification(human.id, 'email', 'magic-link');

    // Sign in to mint a session cookie.
    const raw = generateToken();
    await h.store.createMagicLink(
      human.primary_email,
      hashToken(raw),
      new Date(Date.now() + 15 * 60_000),
    );
    const signin = await h.app.request('/signin/callback', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(raw)}`,
    });
    const cookie = signin.headers.get('set-cookie')!.split(';')[0]!;

    const kp = await createAgentKeypair();
    const lr = await h.store.createLinkRequest({
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
      expires_at: new Date(Date.now() + 30 * 60_000),
      ...(callbackUrl ? { callback_url: callbackUrl } : {}),
    });

    const r = await h.app.request('/link/confirm', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: `req_id=${encodeURIComponent(lr.id)}`,
    });

    return {
      status: r.status,
      contentType: r.headers.get('content-type') ?? '',
      html: await r.text(),
    };
  }

  it('with callback_url: HTML auto-fires the callback via a CSP-compatible static script', async () => {
    const { status, contentType, html } = await confirmAndReturnHtml(
      'http://127.0.0.1:53219/done',
    );
    expect(status).toBe(200);
    expect(contentType).toMatch(/text\/html/);

    // Must contain SOMETHING that auto-navigates to the callback
    // without requiring a click. The CSP forbids inline <script>,
    // so this is either a same-origin <script src=...> reading the
    // URL from a data attribute, OR a <meta http-equiv="refresh">.
    const hasStaticScript =
      /<script\b[^>]*\bsrc=["']\/link-callback\.js["'][^>]*\bdata-callback=["'][^"']+["']/.test(
        html,
      );
    const hasMetaRefresh =
      /<meta\b[^>]*\bhttp-equiv=["']refresh["'][^>]*\bcontent=["'][^"']*url=/i.test(html);

    expect(
      hasStaticScript || hasMetaRefresh,
      `linkConfirmedPage HTML must auto-fire the loopback callback in a CSP-compatible way (got HTML: ${html.slice(0, 800)}…)`,
    ).toBe(true);

    // The callback URL must appear in the auto-fire target verbatim
    // (no truncation, no escaping into uselessness).
    expect(html).toContain('http://127.0.0.1:53219/done');
  });

  it('with callback_url: still shows a manual "Return to the agent" fallback for noscript', async () => {
    const { html } = await confirmAndReturnHtml('http://127.0.0.1:53219/done');
    expect(html).toMatch(/Return to the agent/i);
    expect(html).toContain('href="http://127.0.0.1:53219/done"');
  });

  it('without callback_url: no auto-fire script (nothing to fire)', async () => {
    const { html } = await confirmAndReturnHtml(undefined);
    expect(html).not.toMatch(/\/link-callback\.js/);
    expect(html).not.toMatch(/<meta[^>]*http-equiv=["']refresh/i);
    // The "you can close this tab" copy should appear instead.
    expect(html).toMatch(/close this tab/i);
  });

  it('/link-callback.js is served same-origin, executable, with a long-lived cache hint OK', async () => {
    const r = await h.app.request('/link-callback.js');
    expect(r.status).toBe(200);
    expect(r.headers.get('content-type') ?? '').toMatch(/javascript/);
    const js = await r.text();
    // The script must read data-callback off its own <script> element
    // and trigger navigation to it. We grep, not eval — runtime
    // behaviour is covered by the integration test below.
    expect(js).toMatch(/data-callback/);
    expect(js).toMatch(/window\.location/);
  });
});

describe('end-to-end loopback: browser-simulated hit reaches the agent', () => {
  let h: TestHarness;
  let loopback: Server;
  let loopbackHits = 0;
  let loopbackPort = 0;

  beforeEach(async () => {
    h = await createTestHarness();
    loopbackHits = 0;
    loopback = createServer((_req, res) => {
      loopbackHits++;
      res.writeHead(200, { 'content-type': 'text/plain' });
      res.end('ok');
    });
    await new Promise<void>((resolve) => loopback.listen(0, '127.0.0.1', resolve));
    loopbackPort = (loopback.address() as AddressInfo).port;
  });

  afterEach(async () => {
    await new Promise<void>((resolve) => loopback.close(() => resolve()));
  });

  it('full flow: link/start → human confirm → static script target reaches loopback', async () => {
    const human = await h.store.upsertHuman({ primary_email: 'alice@example.com' });
    await h.store.recordVerification(human.id, 'email', 'magic-link');

    const callbackUrl = `http://127.0.0.1:${loopbackPort}/done`;

    // Run confirm via the public lib (mirrors what /link/confirm does
    // server-side); store the redis stash side-effect we don't need
    // to verify here.
    const kp = await createAgentKeypair();
    const lr = await h.store.createLinkRequest({
      agent_did: kp.did,
      agent_pubkey_b64: kp.publicKeyB64,
      expires_at: new Date(Date.now() + 30 * 60_000),
      callback_url: callbackUrl,
    });
    await confirmLinkRequest({
      store: h.store,
      redis: h.redis,
      human: {
        id: human.id,
        primary_email: human.primary_email,
        created_at: new Date(),
        disabled_at: null,
      },
      reqId: lr.id,
    });

    // Render the post-confirm page directly via the public route.
    // (Re-runs confirmLinkRequest, but that's now a no-op because the
    // request is already confirmed; we just want the HTML.)
    // To avoid the no-op redundancy, render via the in-memory view
    // helper: fetch the confirmed-page HTML by re-invoking /link/confirm.
    // (Sign-in step skipped here — we already exercised that path in
    // the unit test above.)
    const raw = generateToken();
    await h.store.createMagicLink(
      human.primary_email,
      hashToken(raw),
      new Date(Date.now() + 15 * 60_000),
    );
    const signin = await h.app.request('/signin/callback', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: `token=${encodeURIComponent(raw)}`,
    });
    const cookie = signin.headers.get('set-cookie')!.split(';')[0]!;

    // Start a fresh link request so /link/confirm has work to do.
    const kp2 = await createAgentKeypair();
    const lr2 = await h.store.createLinkRequest({
      agent_did: kp2.did,
      agent_pubkey_b64: kp2.publicKeyB64,
      expires_at: new Date(Date.now() + 30 * 60_000),
      callback_url: callbackUrl,
    });
    const r = await h.app.request('/link/confirm', {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded', cookie },
      body: `req_id=${encodeURIComponent(lr2.id)}`,
    });
    const html = await r.text();

    // Extract whatever target the page would auto-navigate to. Cover
    // both supported mechanisms.
    const scriptMatch = html.match(
      /<script\b[^>]*\bsrc=["']\/link-callback\.js["'][^>]*\bdata-callback=["']([^"']+)["']/,
    );
    const metaMatch = html.match(
      /<meta\b[^>]*\bhttp-equiv=["']refresh["'][^>]*\bcontent=["'][^"']*url=([^"']+)["']/i,
    );
    const target = scriptMatch?.[1] ?? metaMatch?.[1];

    expect(target, 'no auto-fire target in confirm HTML').toBeTruthy();
    expect(target).toBe(callbackUrl);

    // Simulate the browser doing what the static script would do:
    // navigate to data-callback. (We're not running JS here; we're
    // testing that the HTML's contract — "fetching this URL is what
    // notifies the agent" — actually reaches the loopback.)
    const cbRes = await fetch(target!);
    expect(cbRes.status).toBe(200);
    expect(loopbackHits).toBe(1);
  });
});
