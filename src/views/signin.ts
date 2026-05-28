import { html, raw } from 'hono/html';

/**
 * Google "G" mark — the official 4-color logo. Per Google's branding
 * guidelines, the SVG paths and fill colors are not modifiable; only
 * the surrounding button (color, font, padding) can be themed. We
 * embed it inline so the button works under our strict CSP without
 * any external asset request.
 *
 * https://developers.google.com/identity/branding-guidelines
 */
const GOOGLE_G_SVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="18" height="18" aria-hidden="true">
  <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
  <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
  <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
  <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
</svg>`;

const SIGNIN_STYLE = `
  .signin-google {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 10px;
    width: 100%;
    height: 44px;
    padding: 0 12px;
    background: #ffffff;
    color: #1f1f1f;
    border: 1px solid #747775;
    border-radius: 6px;
    font-family: -apple-system, BlinkMacSystemFont, 'Roboto', 'Segoe UI', system-ui, sans-serif;
    font-weight: 500;
    font-size: 15px;
    text-decoration: none;
    cursor: pointer;
  }
  .signin-google:hover { background: #f8f9fa; color: #1f1f1f; }
  .signin-google svg { flex: none; }
  .signin-other {
    margin-top: 22px;
    max-width: 420px;
  }
  .signin-other > summary {
    list-style: none;
    cursor: pointer;
    color: var(--muted);
    font-size: 14px;
    padding: 8px 0;
    user-select: none;
  }
  .signin-other > summary::-webkit-details-marker { display: none; }
  .signin-other > summary:hover { color: var(--accent); }
  .signin-other[open] > summary { margin-bottom: 6px; }
  .signin-divider {
    border: none;
    border-top: 1px solid var(--line);
    margin: 22px 0 0;
    max-width: 420px;
  }
`;

export function signinPage(opts: { next?: string; googleEnabled?: boolean }) {
  const googleHref = opts.next
    ? `/auth/google/start?next=${encodeURIComponent(opts.next)}`
    : '/auth/google/start';

  // When Google is disabled, the email form is the only sign-in path
  // and is rendered without the disclosure wrapper.
  if (!opts.googleEnabled) {
    return html`
      <h1>Sign in</h1>
      <p class="lede">
        Enter your email; we'll send you a one-time sign-in link.
      </p>
      ${emailForm(opts.next)}
      <p style="margin-top: 28px; font-size: 13px; color: var(--muted);">
        Sign-in with Google ships when the operator configures OAuth
        credentials. Payment-card verification ships in a future
        revision.
      </p>
    `;
  }

  return html`
    <style>${raw(SIGNIN_STYLE)}</style>
    <h1>Sign in</h1>
    <p class="lede">Sign in to your AFAuth account.</p>
    <div style="max-width: 420px;">
      <a class="signin-google" href="${googleHref}">
        ${raw(GOOGLE_G_SVG)}
        <span>Continue with Google</span>
      </a>
    </div>
    <hr class="signin-divider">
    <details class="signin-other">
      <summary>Sign in with email instead</summary>
      <p style="font-size: 13px; color: var(--muted); margin-top: 4px;">
        We'll send a one-time sign-in link. Use this if you don't want
        to link a Google account.
      </p>
      ${emailForm(opts.next)}
    </details>
    <p style="margin-top: 28px; font-size: 13px; color: var(--muted);">
      Payment-card verification ships in a future revision.
    </p>
  `;
}

function emailForm(next: string | undefined) {
  return html`
    <form class="stack" method="post" action="/signin">
      ${next ? html`<input type="hidden" name="next" value="${next}">` : ''}
      <label>
        Email
        <input type="email" name="email" required autocomplete="email">
      </label>
      <div>
        <button type="submit" class="btn btn-primary">Send sign-in link</button>
      </div>
    </form>
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
