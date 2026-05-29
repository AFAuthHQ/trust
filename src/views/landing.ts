import { html } from 'hono/html';

export function landingPage() {
  return html`
    <h1 style="font-size: 38px; line-height: 1.12; margin: 0 0 18px;">
      Manage the agents that act for you.
    </h1>
    <p class="lede" style="font-size: 19px; max-width: 60ch;">
      AI agents send you here to confirm a link. You sign in once;
      AFAuth services trust the binding. No service ever sees your email.
    </p>

    <p style="margin-top: 26px;">
      <a href="/signin" class="btn btn-primary" style="font-size: 16px; padding: 12px 22px;">
        Sign in to manage agents
      </a>
    </p>

    <div role="img" aria-label="Flow: agent asks to link, you verify once, services trust the signal"
         style="display: flex; align-items: stretch; gap: 0; margin: 36px 0 8px; border: 1px solid var(--line); border-radius: 6px; overflow: hidden; background: var(--paper);">
      <div style="flex: 1; padding: 14px 16px; text-align: center;">
        <div style="font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; text-transform: uppercase; letter-spacing: 0.14em; color: var(--muted); margin-bottom: 6px;">agent</div>
        <div style="font-size: 14px;">asks to link</div>
      </div>
      <div style="width: 1px; background: var(--line);"></div>
      <div style="flex: 1; padding: 14px 16px; text-align: center; background: rgba(184, 50, 39, 0.05);">
        <div style="font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; text-transform: uppercase; letter-spacing: 0.14em; color: var(--accent); margin-bottom: 6px;">you</div>
        <div style="font-size: 14px;">verify once</div>
      </div>
      <div style="width: 1px; background: var(--line);"></div>
      <div style="flex: 1; padding: 14px 16px; text-align: center;">
        <div style="font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; text-transform: uppercase; letter-spacing: 0.14em; color: var(--muted); margin-bottom: 6px;">service</div>
        <div style="font-size: 14px;">trusts the signal</div>
      </div>
    </div>

    <h2 style="margin-top: 36px;">What you control</h2>
    <ul style="list-style: none; padding: 0; margin: 0;">
      <li style="display: flex; gap: 12px; margin: 10px 0;">
        <span aria-hidden="true" style="color: #2c6044; font-weight: 700; flex: 0 0 1em;">✓</span>
        <span>Sign in once with email.</span>
      </li>
      <li style="display: flex; gap: 12px; margin: 10px 0;">
        <span aria-hidden="true" style="color: #2c6044; font-weight: 700; flex: 0 0 1em;">✓</span>
        <span>See every linked agent in one place.</span>
      </li>
      <li style="display: flex; gap: 12px; margin: 10px 0;">
        <span aria-hidden="true" style="color: #2c6044; font-weight: 700; flex: 0 0 1em;">✓</span>
        <span>Revoke any agent instantly — tokens expire within 15 minutes.</span>
      </li>
    </ul>

    <h2 style="margin-top: 28px;">What's not shared</h2>
    <ul style="list-style: none; padding: 0; margin: 0;">
      <li style="display: flex; gap: 12px; margin: 10px 0;">
        <span aria-hidden="true" style="color: var(--accent); font-weight: 700; flex: 0 0 1em;">✗</span>
        <span>Services never see your email.</span>
      </li>
      <li style="display: flex; gap: 12px; margin: 10px 0;">
        <span aria-hidden="true" style="color: var(--accent); font-weight: 700; flex: 0 0 1em;">✗</span>
        <span>Services never see what other services you use.</span>
      </li>
      <li style="display: flex; gap: 12px; margin: 10px 0;">
        <span aria-hidden="true" style="color: var(--accent); font-weight: 700; flex: 0 0 1em;">✗</span>
        <span>Tokens carry &ldquo;verified human&rdquo; — nothing else.</span>
      </li>
    </ul>

    <h2 style="margin-top: 28px;">Verification methods</h2>
    <p style="display: flex; flex-wrap: wrap; gap: 8px; margin: 0;">
      <span class="pill pill-ok">email · live</span>
      <span class="pill pill-ok">oauth · live</span>
      <span class="pill pill-dim">payment · scaffolded</span>
    </p>

    <section style="margin-top: 56px; padding-top: 32px; border-top: 1px solid var(--line);">
      <h2 style="margin-top: 0;">For service developers</h2>
      <p>
        Accept <code>afauth-trust</code> tokens with the bundled
        verifier from <code>@afauthhq/server</code>:
      </p>
      <pre style="background: var(--code); padding: 12px 14px; border-radius: 4px; overflow-x: auto; font-size: 12px;"><code>import { Server, trustAttestor } from '@afauthhq/server';

new Server({
  attestor: trustAttestor(),
  acceptedAttestors: ['afauth-trust'],
});</code></pre>

      <h3 style="margin-top: 28px;">Token claims</h3>
      <table style="width: 100%; border-collapse: collapse; font-size: 14px; margin: 8px 0 0;">
        <thead>
          <tr style="border-bottom: 1px solid var(--line);">
            <th style="text-align: left; padding: 10px 12px 10px 0; font-weight: 600; width: 30%; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;">Claim</th>
            <th style="text-align: left; padding: 10px 0; font-weight: 600; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;">Value</th>
          </tr>
        </thead>
        <tbody>
          <tr style="border-bottom: 1px solid var(--line);"><td style="padding: 10px 12px 10px 0; vertical-align: top;"><code>iss</code></td><td style="padding: 10px 0;">Always <code>"afauth-trust"</code>.</td></tr>
          <tr style="border-bottom: 1px solid var(--line);"><td style="padding: 10px 12px 10px 0; vertical-align: top;"><code>aud</code></td><td style="padding: 10px 0;">Destination <code>service_did</code>. Reject mismatches.</td></tr>
          <tr style="border-bottom: 1px solid var(--line);"><td style="padding: 10px 12px 10px 0; vertical-align: top;"><code>sub</code></td><td style="padding: 10px 0;">The agent's account DID.</td></tr>
          <tr style="border-bottom: 1px solid var(--line);"><td style="padding: 10px 12px 10px 0; vertical-align: top;"><code>sub_h</code></td><td style="padding: 10px 0;">Pairwise human pseudonym. Stable per <code>(iss, sub_h, aud)</code>, opaque base64url. Use as a per-service handle for the human behind the agent.</td></tr>
          <tr style="border-bottom: 1px solid var(--line);"><td style="padding: 10px 12px 10px 0; vertical-align: top;"><code>verification</code></td><td style="padding: 10px 0;"><code>"email"</code>, <code>"oauth"</code>, or <code>"payment"</code>. Ignore unknown values.</td></tr>
          <tr style="border-bottom: 1px solid var(--line);"><td style="padding: 10px 12px 10px 0; vertical-align: top;"><code>iat</code></td><td style="padding: 10px 0;">Issued-at, Unix seconds.</td></tr>
          <tr><td style="padding: 10px 12px 10px 0; vertical-align: top;"><code>exp</code></td><td style="padding: 10px 0;">At most 900 seconds after <code>iat</code>.</td></tr>
        </tbody>
      </table>

      <h3 style="margin-top: 28px;">JWKS endpoint</h3>
      <p>
        Tokens verify offline against the published keys:
      </p>
      <p style="margin: 0 0 6px;">
        <code class="mono">https://trust.afauth.org/.well-known/jwks.json</code>
      </p>
      <p style="font-size: 14px; color: var(--muted); margin: 0;">
        Cached 300 seconds. No runtime call to this service during request handling.
      </p>

      <h3 style="margin-top: 28px;">Rate limits</h3>
      <table style="width: 100%; border-collapse: collapse; font-size: 14px; margin: 8px 0 0;">
        <thead>
          <tr style="border-bottom: 1px solid var(--line);">
            <th style="text-align: left; padding: 10px 12px 10px 0; font-weight: 600; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;">Endpoint</th>
            <th style="text-align: left; padding: 10px 0; font-weight: 600; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em;">Limit</th>
          </tr>
        </thead>
        <tbody>
          <tr style="border-bottom: 1px solid var(--line);"><td style="padding: 10px 12px 10px 0;"><code>POST /v1/link/start</code></td><td style="padding: 10px 0;">30 / minute per IP</td></tr>
          <tr style="border-bottom: 1px solid var(--line);"><td style="padding: 10px 12px 10px 0;"><code>POST /v1/link/poll</code></td><td style="padding: 10px 0;">60 / minute per IP</td></tr>
          <tr><td style="padding: 10px 12px 10px 0;"><code>POST /v1/token</code></td><td style="padding: 10px 0;">60 / minute per IP, 1000 / day per binding</td></tr>
        </tbody>
      </table>

      <p style="margin-top: 28px; font-size: 14px; color: var(--muted);">
        Wire surface specified in
        <a href="https://github.com/AFAuthHQ/spec/blob/main/proposals/0006-afauth-trust-attestor.md" target="_blank" rel="noopener">AFAP-0006</a>.
        Source at
        <a href="https://github.com/AFAuthHQ/trust" target="_blank" rel="noopener">github.com/AFAuthHQ/trust</a>.
      </p>
    </section>
  `;
}
