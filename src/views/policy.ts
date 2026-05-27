import { html } from 'hono/html';

export function policyPage() {
  return html`
    <h1>Take-down policy</h1>
    <p>
      This page governs revocation and account-disable decisions on
      <code>trust.afauth.org</code>. It applies only to this operator;
      a future operator running their own trust attestor sets their
      own policy.
    </p>

    <h2>Categories</h2>
    <p>We may revoke a binding or disable an account when:</p>
    <ul>
      <li><strong>Bulk-registered accounts.</strong> Accounts created
        at a rate inconsistent with one human per account, with no
        evidence of a legitimate organisational use.</li>
      <li><strong>Verified-method abuse.</strong> Email magic links
        forwarded between humans to share a single account, payment
        cards re-used across accounts beyond reasonable shared-card
        scenarios, or other patterns inconsistent with one human
        controlling the verification.</li>
      <li><strong>Agent linked to known-malicious behaviour.</strong>
        Repeated reports from consuming services about a specific
        <code>agent_did</code> engaged in spam, credential stuffing,
        scraping past published rate limits, or generating illegal
        content. Reports must include enough evidence for a
        reasonable determination.</li>
      <li><strong>Fraudulent verification claims.</strong> Email or
        OAuth identities asserted by an account that the
        upstream provider can show the account does not control.</li>
      <li><strong>Illegal activity</strong> under applicable law.</li>
    </ul>

    <h2>Revoke vs disable</h2>
    <p>
      <strong>Revoke binding</strong>: invalidates the long-lived
      binding token for a single agent. The human's account and
      verifications remain; they can re-link the same or a different
      agent immediately. This is the default action for
      agent-specific issues.
    </p>
    <p>
      <strong>Disable account</strong>: invalidates the binding
      tokens for every agent linked to the account and prevents new
      bindings. The human's verifications remain on file for audit.
      Reserved for category-1 (bulk) and category-4 (fraud) findings.
    </p>
    <p>
      Either action affects only token issuance going forward. Per
      AFAP-0006, JWTs already issued remain valid for up to
      <strong>15 minutes</strong> (the maximum <code>exp - iat</code>).
      This is the spec's revocation-latency bound and is intentional —
      offline verification is what makes the attestor reliable.
    </p>

    <h2>Account deletion (operator-initiated)</h2>
    <p>
      Account deletion — full removal of the <code>humans</code>
      row, verifications, and bindings — is currently a manual
      operator process initiated by emailing
      <a href="mailto:[email protected]">[email protected]</a>
      from the account's verified email address. Self-serve deletion
      is on the v0.2 roadmap.
    </p>

    <h2>Reports</h2>
    <p>Send reports to
      <a href="mailto:[email protected]">[email protected]</a>.
      Include:
    </p>
    <ul>
      <li>The <code>agent_did</code> (or <code>verification</code>
        value pattern, for systemic abuse).</li>
      <li>Which category above applies.</li>
      <li>Evidence — logs, request payloads, screenshots, links to
        third-party advisories — sufficient for the operator to
        reach a reasonable determination.</li>
    </ul>
    <p>
      We acknowledge reports within five business days during this
      working-draft phase, and publish anonymised aggregate
      statistics annually.
    </p>

    <h2>Re-link after revocation</h2>
    <p>
      A human whose binding was revoked due to a single agent's
      behaviour may re-link a fresh agent identity (new
      <code>did:key</code> or rotated keypair) without contacting
      the operator. A revocation of binding does not signal that
      the human is in bad standing — it signals that the specific
      agent was operating outside accepted patterns.
    </p>
    <p>
      An account that has been disabled (not just had a binding
      revoked) may appeal by emailing the operator with context.
      The verification path used to register the account is the
      authoritative channel — appeals from other addresses will be
      directed back to it.
    </p>

    <h2>What this policy does not commit</h2>
    <p>
      This policy governs the operator's discretionary action; it
      does not promise that consuming services will treat any
      particular signal a particular way. AFAP-0006 §10.3.1 makes
      that decision explicitly local to each service.
    </p>
  `;
}
