import { html } from 'hono/html';

export function signinPage(opts: { next?: string; googleEnabled?: boolean }) {
  const googleHref = opts.next
    ? `/auth/google/start?next=${encodeURIComponent(opts.next)}`
    : '/auth/google/start';
  return html`
    <h1>Sign in</h1>
    <p class="lede">
      ${opts.googleEnabled
        ? html`Continue with Google, or get a one-time link by email.`
        : html`Enter your email; we'll send you a one-time sign-in link.`}
    </p>
    ${opts.googleEnabled
      ? html`
          <div style="max-width: 420px; margin-bottom: 14px;">
            <a class="btn" href="${googleHref}" style="width: 100%; justify-content: center;">
              Continue with Google
            </a>
          </div>
          <div style="display: flex; align-items: center; gap: 10px; max-width: 420px; margin: 18px 0; color: var(--muted); font-size: 13px;">
            <hr style="flex: 1; border: none; border-top: 1px solid var(--line); margin: 0;">
            <span>or</span>
            <hr style="flex: 1; border: none; border-top: 1px solid var(--line); margin: 0;">
          </div>
        `
      : ''}
    <form class="stack" method="post" action="/signin">
      ${opts.next ? html`<input type="hidden" name="next" value="${opts.next}">` : ''}
      <label>
        Email
        <input type="email" name="email" required autocomplete="email" autofocus>
      </label>
      <div>
        <button type="submit" class="btn btn-primary">Send sign-in link</button>
      </div>
    </form>
    <p style="margin-top: 28px; font-size: 13px; color: var(--muted);">
      ${opts.googleEnabled
        ? html`Payment-card verification ships in a future revision.`
        : html`Email is the only verification method available at v0.1. OAuth
          (Google, GitHub) and payment-card verification ship in future
          revisions.`}
    </p>
  `;
}

export function signinSentPage(opts: { email: string }) {
  return html`
    <h1>Check your inbox</h1>
    <p class="lede">
      We sent a sign-in link to <strong>${opts.email}</strong>.
    </p>
    <p>The link expires in 15 minutes. You can close this tab.</p>
  `;
}

/**
 * Rendered on GET /signin/callback?token=... after we've verified the
 * token exists but BEFORE we consume it. The user clicks the form
 * button to POST and complete signin.
 *
 * The two-step pattern (consent page → POST) is the load-bearing
 * defence against URL pre-fetchers (Microsoft 365 SafeLinks, Gmail
 * spam scanners, corporate egress proxies). Those tools GET email
 * links to scan for malware; a GET that consumed the token would
 * leave the human staring at "link already used" when they finally
 * click. RFC 9110 also requires GET to be safe / idempotent.
 */
export function signinCallbackPage(opts: {
  email: string;
  token: string;
}) {
  return html`
    <h1>Sign in to AFAuth</h1>
    <p class="lede">
      Confirm you want to sign in as <strong>${opts.email}</strong>.
    </p>
    <form method="post" action="/signin/callback" class="stack">
      <input type="hidden" name="token" value="${opts.token}">
      <div style="display: flex; gap: 8px;">
        <button type="submit" class="btn btn-primary">
          Sign in as ${opts.email}
        </button>
        <a href="/" class="btn">Cancel</a>
      </div>
    </form>
    <p style="margin-top: 28px; font-size: 13px; color: var(--muted);">
      Not you, or didn't request this? Close this tab — nothing
      happens until you click. The link expires automatically.
    </p>
  `;
}

export function signinCallbackErrorPage(opts: { message: string }) {
  return html`
    <h1>Link unavailable</h1>
    <p class="lede">${opts.message}</p>
    <p>
      <a href="/signin" class="btn">Send a new sign-in link</a>
    </p>
  `;
}
