import { getConfig } from '../config.js';
import { getLogger } from '../logger.js';

/**
 * Sends a magic-link email.
 *
 * Providers:
 *
 *   stdout   — log to stderr; for dev / `pnpm dev` flows where you
 *              copy the link out of the terminal.
 *
 *   resend   — POST to https://api.resend.com/emails. Set
 *              EMAIL_API_KEY to your `re_...` key. Free tier allows
 *              up to 100 emails/day per domain at the time of writing.
 *
 *   postmark — stubbed; not implemented. The provider call is one
 *              fetch away (POST https://api.postmarkapp.com/email
 *              with X-Postmark-Server-Token header) but I've left it
 *              out until someone needs it.
 */
export async function sendMagicLink(opts: {
  to: string;
  link: string;
}): Promise<void> {
  const cfg = getConfig();
  const log = getLogger();

  if (cfg.EMAIL_PROVIDER === 'stdout') {
    log.info({ to: opts.to, link: opts.link }, 'magic link (stdout provider)');
    return;
  }

  if (!cfg.EMAIL_API_KEY) {
    throw new Error(`EMAIL_API_KEY required for provider=${cfg.EMAIL_PROVIDER}`);
  }

  const subject = 'Sign in to trust.afauth.org';
  const text = [
    `Click to sign in to your AFAuth trust account:`,
    ``,
    opts.link,
    ``,
    `This link expires in 15 minutes. If you didn't request it, ignore this email.`,
  ].join('\n');
  const html = renderMagicLinkHtml(opts.link);

  switch (cfg.EMAIL_PROVIDER) {
    case 'resend':
      await sendViaResend({
        apiKey: cfg.EMAIL_API_KEY,
        from: cfg.EMAIL_FROM,
        to: opts.to,
        subject,
        text,
        html,
      });
      return;
    case 'postmark':
      log.warn(
        { provider: cfg.EMAIL_PROVIDER, to: opts.to },
        'postmark provider not yet implemented; would send magic link',
      );
      log.info({ subject, text }, 'magic link body');
      return;
  }
}

async function sendViaResend(args: {
  apiKey: string;
  from: string;
  to: string;
  subject: string;
  text: string;
  html: string;
}): Promise<void> {
  const resp = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      authorization: `Bearer ${args.apiKey}`,
    },
    body: JSON.stringify({
      from: args.from,
      to: args.to,
      subject: args.subject,
      text: args.text,
      html: args.html,
    }),
  });
  if (!resp.ok) {
    let detail = `${resp.status} ${resp.statusText}`;
    try {
      const body = await resp.json();
      const msg = (body as { message?: string }).message;
      if (msg) detail = `${detail}: ${msg}`;
    } catch {
      // Ignore body-parse errors.
    }
    throw new Error(`resend: failed to send magic link: ${detail}`);
  }
}

function renderMagicLinkHtml(link: string): string {
  // Plain inline-styled HTML — no external assets, no images, no
  // tracking pixel. Renders consistently across Gmail, Apple Mail,
  // Outlook.com. Neutral ink palette on white — auth emails should
  // read calm, not alarming (red == security-warning in most users'
  // mental models, exactly the tone we want to avoid).
  return `<!doctype html>
<html lang="en">
<body style="margin:0;padding:32px 16px;font-family:-apple-system,Segoe UI,sans-serif;background:#ffffff;color:#1c1816;">
  <div style="max-width:480px;margin:0 auto;background:#ffffff;border:1px solid #e5e0d6;border-radius:6px;padding:32px;">
    <h1 style="margin:0 0 16px;font-size:22px;color:#1c1816;">Sign in to AFAuth</h1>
    <p style="margin:0 0 24px;">Click below to sign in. The link expires in 15 minutes.</p>
    <p style="margin:0 0 32px;">
      <a href="${escapeHtml(link)}"
         style="display:inline-block;padding:12px 22px;background:#1c1816;color:#ffffff;text-decoration:none;border-radius:4px;font-weight:600;">
        Sign in
      </a>
    </p>
    <p style="margin:0;font-size:13px;color:#5e564f;">
      If the button doesn't work, paste this URL into your browser:<br>
      <span style="font-family:ui-monospace,Menlo,monospace;font-size:12px;word-break:break-all;">${escapeHtml(link)}</span>
    </p>
    <p style="margin:24px 0 0;font-size:12px;color:#5e564f;">
      Didn't request this? Ignore the email — nothing happens until you click.
    </p>
  </div>
</body>
</html>`;
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
