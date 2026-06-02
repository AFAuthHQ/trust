import { html } from 'hono/html';
import type {
  BindingRecord,
  HumanRecord,
  VerificationRecord,
} from '../lib/store/index.js';
import type { VerificationMethod } from '../lib/schemas.js';

interface RecentToken {
  binding_id: string;
  agent_did: string;
  service_did: string;
  verification: VerificationMethod;
  issued_at: Date;
}

export function accountPage(opts: {
  human: HumanRecord;
  verifications: VerificationRecord[];
  bindings: BindingRecord[];
  recentTokens: RecentToken[];
  googleEnabled?: boolean;
}) {
  const { human, verifications, bindings, recentTokens, googleEnabled } = opts;
  const googleVerification = verifications.find(
    (v) => v.method === 'oauth' && v.provider === 'google',
  );

  return html`
    <div style="display: flex; justify-content: space-between; align-items: baseline;">
      <h1 style="margin: 0;">Account</h1>
      <form method="post" action="/signout" style="margin: 0;">
        <button class="btn" type="submit">Sign out</button>
      </form>
    </div>
    <p class="lede mono" style="font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 14px;">
      ${human.primary_email}
    </p>

    <h2>Verifications</h2>
    <div class="card">
      ${(() => {
        // Collapse all email rows into one card — the email address is
        // a property of the human, not the verification, so the
        // (human, email) pair is the same regardless of how many
        // providers verified it (magic-link, google-verified, etc.).
        // Show the earliest verified_at so the date doesn't bounce as
        // new providers attest the same email.
        const emailVerifs = verifications.filter((v) => v.method === 'email');
        if (emailVerifs.length === 0) {
          return html`
            <div class="card-row">
              <div>
                <strong>Email</strong>
                <span class="pill pill-warn">not verified</span>
              </div>
              <a href="/signin" class="btn">Verify</a>
            </div>
          `;
        }
        const earliest = emailVerifs.reduce((a, b) =>
          a.verified_at.getTime() < b.verified_at.getTime() ? a : b,
        );
        return html`
          <div class="card-row">
            <div>
              <strong>Email</strong>
              <span class="pill pill-ok">verified</span>
              <div class="meta">${human.primary_email}</div>
              <div class="meta">since ${earliest.verified_at.toISOString().slice(0, 10)}</div>
            </div>
          </div>
        `;
      })()}
    </div>

    <div class="card">
      <div class="card-row">
        <div>
          <strong>Google</strong>
          ${googleVerification
            ? html`
                <span class="pill pill-ok">connected</span>
                <div class="meta">
                  since ${googleVerification.verified_at.toISOString().slice(0, 10)}
                </div>
              `
            : googleEnabled
              ? html`<span class="pill pill-dim">not connected</span>`
              : html`<span class="pill pill-dim">coming soon</span>`}
          <div class="meta">
            Verifies your identity via Google. Upgrades the
            <code>verification</code> claim on issued tokens from
            <code>email</code> to <code>oauth</code>.
          </div>
        </div>
        ${googleVerification
          ? html`
              <form method="post" action="/auth/google/revoke" style="margin: 0;">
                <button class="btn btn-danger" type="submit">Disconnect</button>
              </form>
            `
          : googleEnabled
            ? html`<a class="btn" href="/auth/google/start?next=%2Faccount">Connect</a>`
            : html`<button class="btn" disabled>Connect</button>`}
      </div>
    </div>

    <div class="card">
      <div class="card-row">
        <div>
          <strong>Payment card</strong>
          <span class="pill pill-dim">coming v0.3</span>
          <div class="meta">Verify a card via Stripe SetupIntent (no charge).</div>
        </div>
        <button class="btn" disabled>Add</button>
      </div>
    </div>

    <h2>Linked agents (${bindings.filter((b) => !b.revoked_at).length})</h2>
    ${bindings.filter((b) => !b.revoked_at).length > 0
      ? html`
          <p style="margin: 0 0 12px; font-size: 13px; color: var(--muted);">
            Lost a key or suspect one agent is compromised? Revoke it to
            cut it off — recovery is per agent. Revoking takes effect
            within 15 minutes (AFAuth's revocation bound); tokens minted
            before revocation stay valid until they expire (max 15 min).
          </p>
        `
      : ''}
    ${bindings.length === 0
      ? html`
          <div class="card">
            <p style="margin: 0;">
              No agents linked yet. Agents request a link by calling
              <code>POST /v1/link/start</code> and surfacing the
              resulting deep link to you.
            </p>
          </div>
        `
      : bindings.map(
          (b) => html`
            <div class="card">
              <div class="card-row">
                <div style="flex: 1; min-width: 0;">
                  <div class="did">${b.agent_did}</div>
                  ${b.agent_label
                    ? html`<div class="meta">"${b.agent_label}"</div>`
                    : ''}
                  <div class="meta">
                    linked ${b.created_at.toISOString().slice(0, 10)}
                    ${b.last_used_at
                      ? html` · last token ${formatRelative(b.last_used_at)}`
                      : ''}
                    ${b.revoked_at
                      ? html` · <span class="pill pill-warn">revoked</span>`
                      : ''}
                  </div>
                </div>
                ${b.revoked_at
                  ? ''
                  : html`
                      <form method="post" action="/account/bindings/${b.id}/revoke" style="margin: 0;">
                        <button type="submit" class="btn btn-danger">Revoke</button>
                      </form>
                    `}
              </div>
            </div>
          `,
        )}

    <h2>Account status</h2>
    ${human.disabled_at
      ? html`
          <div class="card">
            <div class="card-row">
              <div>
                <strong>Disabled</strong>
                <span class="pill pill-warn">disabled</span>
                <div class="meta">
                  Disabled ${human.disabled_at.toISOString().slice(0, 10)}.
                  The attestor issues no new tokens for any of your agents
                  while this account is disabled. Tokens minted before you
                  disabled may stay valid at services until they expire
                  (max 15 min).
                </div>
                <div class="meta">Re-enabling requires a fresh sign-in.</div>
              </div>
              <form method="post" action="/account/enable" style="margin: 0;">
                <button type="submit" class="btn">Re-enable account</button>
              </form>
            </div>
          </div>
        `
      : html`
          <div class="card">
            <div class="card-row">
              <div>
                <strong>Active</strong>
                <span class="pill pill-ok">active</span>
                <div class="meta">
                  Suspect a compromise? Disabling immediately stops the
                  attestor from issuing new tokens for every agent linked
                  to this account at once. Already-issued tokens stay valid
                  until they expire (max 15 min). You can re-enable anytime.
                </div>
              </div>
              <form method="post" action="/account/disable" style="margin: 0;">
                <button type="submit" class="btn btn-danger">Disable account</button>
              </form>
            </div>
          </div>
        `}

    ${recentTokens.length > 0
      ? html`
          <h2>Recent tokens</h2>
          <div class="card">
            <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
              <thead>
                <tr style="text-align: left; color: var(--muted);">
                  <th style="padding: 4px 8px;">when</th>
                  <th style="padding: 4px 8px;">audience</th>
                  <th style="padding: 4px 8px;">verification</th>
                </tr>
              </thead>
              <tbody>
                ${recentTokens.map(
                  (t) => html`
                    <tr>
                      <td style="padding: 4px 8px;">${formatRelative(t.issued_at)}</td>
                      <td style="padding: 4px 8px;" class="mono">${t.service_did}</td>
                      <td style="padding: 4px 8px;">
                        <span class="pill pill-ok">${t.verification}</span>
                      </td>
                    </tr>
                  `,
                )}
              </tbody>
            </table>
          </div>
        `
      : ''}

  `;
}

function formatRelative(d: Date): string {
  const seconds = Math.floor((Date.now() - d.getTime()) / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}
