import { html } from 'hono/html';

export function operatorPage() {
  return html`
    <h1>Operator commitment</h1>
    <p>
      <strong>AFAuthHQ</strong> operates <code>trust.afauth.org</code>
      as the reference implementation of the
      <a href="https://github.com/AFAuthHQ/spec/blob/main/proposals/0006-afauth-trust-attestor.md" target="_blank" rel="noopener">AFAP-0006</a>
      trust attestor. This page is the public commitment under which
      we run it.
    </p>
    <p>
      Per AFAP-0006 §10.3 the trust attestor is one of four classes
      of attestor a service MAY accept. Conforming services are not
      required to list <code>afauth-trust</code> in their
      <code>billing.accepted_attestors</code>, and a conforming
      service that ignores this attestor entirely remains conforming.
    </p>

    <h2>Who has operational authority</h2>
    <p>
      AFAuthHQ. Operational contact:
      <a href="mailto:[email protected]">[email protected]</a>.
      Abuse and take-down reports:
      <a href="mailto:[email protected]">[email protected]</a>.
    </p>

    <h2>What we issue, what we don't</h2>
    <p>
      The trust attestor issues short-lived JWTs (≤15 minutes,
      audience-bound to one service) that signal a human-verified
      agent. The token carries a categorical
      <code>verification</code> value (<code>"email"</code>,
      <code>"oauth"</code>, or <code>"payment"</code>) and no
      personal data.
    </p>
    <p>
      The trust attestor takes no opinion on what access a consuming
      service should grant in response to any particular
      verification value. Policy is local to each service.
    </p>

    <h2>Actions we MAY take unilaterally</h2>
    <ul>
      <li>Revoke bindings or disable accounts under the published
        <a href="/policy">take-down policy</a>.</li>
      <li>Rotate signing keys per AFAP-0006 §10.3.1, with the
        mandated ≥900s pre-publication of new <code>kid</code>s in
        the JWKS so consumer caches refresh ahead of first use.</li>
      <li>Infrastructure changes (hosting provider, runtime version,
        internal storage layout) that preserve the wire surface
        defined in AFAP-0006.</li>
      <li>Add verification methods beyond email (OAuth, payment) as
        documented in AFAP-0006 §10.3.1; consuming services MUST
        ignore unknown values per the spec.</li>
    </ul>

    <h2>Actions we MUST NOT take unilaterally</h2>
    <ul>
      <li>Include personal data in JWT claims. AFAP-0006 §10.3.1
        forbids email addresses, phone numbers, payment details, and
        government identifiers in any claim. We honour that limit
        with no exceptions.</li>
      <li>Disable accounts on ideological grounds. Account standing
        derives from the verification methods on file; legitimate
        humans may not be removed for opinions unrelated to the
        moderation policy.</li>
      <li>Make wire-breaking changes to the JWT shape or the JWKS
        endpoint. Those changes require a versioned AFAP revision in
        <a href="https://github.com/AFAuthHQ/spec" target="_blank" rel="noopener">AFAuthHQ/spec</a>
        and a deprecation window.</li>
      <li>Issue an attestation JWT for an agent without an active
        binding to a verified human account, or for any
        <code>aud</code> other than the one the agent requested.</li>
    </ul>

    <h2>Bounded blast radius</h2>
    <p>
      Verification is offline against the JWKs document at
      <code>https://trust.afauth.org/.well-known/jwks.json</code>.
      A brief trust-attestor outage does not interrupt in-flight
      requests at consuming services — only token reissuance is
      affected. The 900-second <code>exp</code> cap bounds
      revocation latency.
    </p>

    <h2>Governance evolution</h2>
    <p>
      AFAuthHQ acts as both spec editor and trust-attestor operator
      at v0.1. AFAP-0006 §Security explicitly acknowledges this and
      anticipates that, if neutrality becomes operationally relevant,
      a future AFAP may move the trust attestor under a distinct
      identifier and entity. The wire shape is unchanged by such a
      move; this page does not commit AFAuthHQ to a specific
      governance trajectory in advance of that evidence.
    </p>
  `;
}
