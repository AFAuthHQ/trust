import { html } from 'hono/html';

export function landingPage() {
  return html`
    <h1>trust.afauth.org</h1>
    <p class="lede">
      The reference operator for the <code>afauth-trust</code>
      attestor — vouches that an agent's identity is bound to a
      human-controlled account.
    </p>

    <p>
      Per
      <a href="https://github.com/AFAuthHQ/spec/blob/main/proposals/0006-afauth-trust-attestor.md" target="_blank" rel="noopener">AFAP-0006</a>,
      this service issues short-lived JWTs that consuming services
      verify offline against
      <code>https://afauth.org/.well-known/jwks.json</code>.
      The token signals only that <em>some</em> human is behind the
      agent and which verification method they used; it carries no
      personal data.
    </p>

    <h2>For humans</h2>
    <p>
      Agents will surface a link asking you to bind them to your
      account. You verify yourself once (email at v0.1); the agent
      can then mint per-service attestation tokens within rate
      limits. <a href="/account">Manage linked agents</a>.
    </p>

    <h2>For services</h2>
    <p>
      Add <code>afauth-trust</code> to your service's
      <code>billing.accepted_attestors</code> list. The reference
      TypeScript SDK ships a pre-configured verifier:
    </p>
    <pre style="background: var(--code); padding: 12px 14px; border-radius: 4px; overflow-x: auto; font-size: 12px;"><code>import { JwksAttestor } from '@afauthhq/server';

const attestor = new JwksAttestor({
  iss: 'afauth-trust',
  jwksUrl: 'https://afauth.org/.well-known/jwks.json',
});</code></pre>

    <h2>For agents</h2>
    <p>
      Use the AFAuth CLI:
    </p>
    <pre style="background: var(--code); padding: 12px 14px; border-radius: 4px; overflow-x: auto; font-size: 12px;"><code>afauth trust link    # surfaces the deep link to the human
afauth trust token did:web:tavily.com</code></pre>
  `;
}
