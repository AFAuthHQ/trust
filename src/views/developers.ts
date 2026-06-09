import { html } from 'hono/html';

export function developersPage() {
  return html`
    <p style="margin: 0 0 18px; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 12px; text-transform: uppercase; letter-spacing: 0.1em;">
      <a href="/" style="color: var(--muted); text-decoration: none;">← trust.afauth.org</a>
    </p>

    <h1 style="margin: 0 0 10px;">For service developers</h1>
    <p class="lede">
      Accept <code>afauth-trust</code> tokens so agents can prove a real human is
      behind them — with no PII for you to store. Wire surface specified in
      <a href="https://github.com/AFAuthHQ/spec/blob/main/proposals/0006-afauth-trust-attestor.md" target="_blank" rel="noopener">AFAP-0006</a>.
    </p>

    <h2 style="margin-top: 32px;">Verify tokens</h2>
    <p>
      Accept <code>afauth-trust</code> tokens with the bundled
      verifier from <code>@afauthhq/server</code>:
    </p>
    <pre style="background: var(--code); padding: 12px 14px; border-radius: 4px; overflow-x: auto; font-size: 12px;"><code>import { Server, trustAttestor } from '@afauthhq/server';

new Server({
  attestor: trustAttestor(),
  acceptedAttestors: ['afauth-trust'],
});</code></pre>

    <h2 style="margin-top: 32px;">Token claims</h2>
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

    <h2 style="margin-top: 32px;">JWKS endpoint</h2>
    <p>
      Tokens verify offline against the published keys:
    </p>
    <p style="margin: 0 0 6px;">
      <code class="mono">https://trust.afauth.org/.well-known/jwks.json</code>
    </p>
    <p style="font-size: 14px; color: var(--muted); margin: 0;">
      Cached 300 seconds. No runtime call to this service during request handling.
    </p>

    <h2 style="margin-top: 32px;">Rate limits</h2>
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

    <p style="margin-top: 32px; font-size: 14px; color: var(--muted);">
      Source at
      <a href="https://github.com/AFAuthHQ/trust" target="_blank" rel="noopener">github.com/AFAuthHQ/trust</a>.
    </p>
  `;
}
