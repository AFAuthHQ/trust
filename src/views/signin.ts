import { html } from 'hono/html';

export function signinPage(opts: { next?: string }) {
  return html`
    <h1>Sign in</h1>
    <p class="lede">
      Enter your email; we'll send you a one-time sign-in link.
    </p>
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
      Email is the only verification method available at v0.1.
      OAuth (Google, GitHub) and payment-card verification ship in
      future revisions.
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
