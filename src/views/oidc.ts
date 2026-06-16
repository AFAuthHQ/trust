import { html } from 'hono/html';

/**
 * OIDC consent page — shown when a relying party sends `prompt=consent` and the
 * human already has a live trust session. It turns the otherwise-silent
 * re-authorization into an explicit confirmation, so an explicit logout from the
 * RP isn't undone by the still-valid trust session with no UI.
 *
 * Two-step (page → POST) like the magic-link callback: a GET never mints a code,
 * so URL pre-fetchers can't authorize on the human's behalf. The form is
 * same-origin, so the global origin-based CSRF guard covers the POST (no token
 * field needed). Privacy property preserved: approving shares only the
 * pseudonymous `sub_h`, never the email.
 */
export function oidcConsentPage(opts: { email: string; clientLabel: string; rid: string }) {
  return html`
    <h1>Authorize sign-in</h1>
    <p class="lede">
      <strong>${opts.clientLabel}</strong> wants to sign you in as
      <strong>${opts.email}</strong>.
    </p>
    <form method="post" action="/oidc/authorize/decision" class="stack">
      <input type="hidden" name="rid" value="${opts.rid}">
      <div style="display: flex; gap: 8px;">
        <button type="submit" name="decision" value="approve" class="btn btn-primary">
          Continue as ${opts.email}
        </button>
        <button type="submit" name="decision" value="deny" class="btn">
          Cancel
        </button>
      </div>
    </form>
    <p style="margin-top: 28px; font-size: 13px; color: var(--muted);">
      You're signed in to AFAuth. Continuing shares only a pseudonymous
      identifier with ${opts.clientLabel} — never your email.
    </p>
  `;
}
