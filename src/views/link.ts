import { html } from 'hono/html';
import type { LinkRequestEnvelope } from '../lib/schemas.js';

export function linkConfirmPage(opts: {
  envelope: LinkRequestEnvelope;
  /** Raw req JWT from the inbound URL, used to bounce through /signin. */
  rawReq: string;
  hasSession: boolean;
  hasEmailVerification: boolean;
}) {
  const { envelope, rawReq, hasSession, hasEmailVerification } = opts;
  const expiresIn = Math.max(0, envelope.exp - Math.floor(Date.now() / 1000));
  const mins = Math.floor(expiresIn / 60);

  const signinNext = `/link?req=${encodeURIComponent(rawReq)}`;

  return html`
    <h1>Link this agent?</h1>

    <p class="lede">
      An agent on your device is asking to act under your AFAuth
      identity. Services will be told a human (you) stands behind
      this agent — they won't see your email or any personal data.
    </p>

    <div class="card">
      <h3 style="margin-top: 0;">Agent</h3>
      <div class="did">${envelope.agent_did}</div>
      ${envelope.agent_label
        ? html`<div class="meta">${envelope.agent_label}</div>`
        : ''}
      <div class="meta">Request expires in ${mins} min</div>
    </div>

    <div class="card">
      <h3 style="margin-top: 0;">What this agent will be able to do</h3>
      <ul style="margin: 0; padding-left: 18px;">
        <li>Request short-lived attestation tokens (max 15 min)
            audience-bound to one service at a time.</li>
        <li>Carry the verification methods you have on file
            (currently: email).</li>
        <li>Be revoked any time from your <a href="/account">account</a>.</li>
      </ul>
    </div>

    ${hasSession
      ? hasEmailVerification
        ? html`
            <form method="post" action="/link/confirm" class="stack">
              <input type="hidden" name="req_id" value="${envelope.req_id}">
              <div style="display: flex; gap: 8px;">
                <button type="submit" class="btn btn-primary">
                  Link this agent
                </button>
                <a href="/" class="btn">Cancel</a>
              </div>
            </form>
          `
        : html`
            <div class="card" style="border-color: var(--accent-dim);">
              <p style="margin: 0;">
                You need at least one verification method before
                linking an agent. <a href="/account">Add one</a>.
              </p>
            </div>
          `
      : html`
          <p>
            <a href="/signin?next=${encodeURIComponent(signinNext)}"
               class="btn btn-primary">
              Sign in to continue
            </a>
          </p>
        `}
  `;
}

export function linkConfirmedPage(opts: { callbackUrl: string | null }) {
  return html`
    <h1>Linked.</h1>
    <p class="lede">
      The agent has been linked to your account. You can manage or
      revoke it any time from <a href="/account">your account</a>.
    </p>
    ${opts.callbackUrl
      ? html`
          <p>
            <a href="${opts.callbackUrl}" class="btn btn-primary">
              Return to the agent
            </a>
          </p>
          <script>
            setTimeout(() => { window.location.href = ${JSON.stringify(opts.callbackUrl)}; }, 1500);
          </script>
        `
      : html`<p>You can close this tab.</p>`}
  `;
}

export function linkErrorPage(opts: { message: string }) {
  return html`
    <h1>Link request unavailable</h1>
    <p class="lede">${opts.message}</p>
    <p>Ask your agent to start a new link request.</p>
  `;
}
