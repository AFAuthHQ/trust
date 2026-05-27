import { html, raw } from 'hono/html';
import type { HtmlEscapedString } from 'hono/utils/html';

const STYLE = `
  :root {
    --fg: #1c1816;
    --muted: #5e564f;
    --bg: #f5efe4;
    --paper: #ffffff;
    --line: #d8cfc3;
    --accent: #B83227;
    --accent-dim: #d8918a;
    --code: #efe8db;
  }
  * { box-sizing: border-box; }
  html, body { margin: 0; padding: 0; }
  body {
    font-family: ui-serif, Georgia, 'Times New Roman', Times, serif;
    color: var(--fg);
    background: var(--bg);
    line-height: 1.55;
    font-size: 17px;
  }
  header.site {
    border-bottom: 1px solid var(--line);
    background: rgba(245, 239, 228, 0.85);
    backdrop-filter: blur(12px);
    position: sticky;
    top: 0;
    z-index: 10;
  }
  header.site nav {
    max-width: 720px;
    margin: 0 auto;
    padding: 14px 24px;
    display: flex;
    gap: 20px;
    align-items: baseline;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 13px;
  }
  header.site nav strong { color: var(--accent); font-weight: 600; }
  header.site nav a { color: var(--fg); text-decoration: none; }
  header.site nav a:hover { color: var(--accent); }
  header.site nav .spacer { flex: 1; }
  main {
    max-width: 720px;
    margin: 0 auto;
    padding: 40px 24px 80px;
  }
  h1 { font-size: 32px; margin: 0 0 16px; line-height: 1.2; }
  h2 { font-size: 20px; margin: 36px 0 12px; }
  h3 { font-size: 16px; margin: 24px 0 8px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.06em; font-weight: 600; }
  p { margin: 0 0 14px; }
  p.lede { font-size: 18px; color: var(--muted); }
  ul { padding-left: 20px; }
  code, .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.92em;
    background: var(--code);
    padding: 1px 6px;
    border-radius: 3px;
  }
  a { color: var(--accent); }

  /* Cards */
  .card {
    background: var(--paper);
    border: 1px solid var(--line);
    border-radius: 6px;
    padding: 20px 24px;
    margin: 16px 0;
  }
  .card + .card { margin-top: 12px; }
  .card-row {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 16px;
  }
  .card .did {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 13px;
    word-break: break-all;
  }
  .card .meta {
    font-size: 13px;
    color: var(--muted);
    margin-top: 6px;
  }

  /* Buttons */
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 16px;
    border-radius: 4px;
    border: 1px solid var(--line);
    background: var(--paper);
    color: var(--fg);
    font: inherit;
    font-size: 14px;
    cursor: pointer;
    text-decoration: none;
  }
  .btn:hover { border-color: var(--accent); color: var(--accent); }
  .btn-primary {
    background: var(--accent);
    color: var(--paper);
    border-color: var(--accent);
  }
  .btn-primary:hover {
    background: #9a2920;
    color: var(--paper);
    border-color: #9a2920;
  }
  .btn-danger {
    color: var(--accent);
    border-color: var(--accent-dim);
  }
  .btn-danger:hover {
    background: var(--accent);
    color: var(--paper);
  }
  .btn[disabled] { opacity: 0.5; cursor: not-allowed; }

  /* Forms */
  form.stack { display: flex; flex-direction: column; gap: 14px; max-width: 420px; }
  label { display: flex; flex-direction: column; gap: 4px; font-size: 14px; color: var(--muted); }
  input[type=email], input[type=text] {
    font: inherit;
    padding: 10px 12px;
    border: 1px solid var(--line);
    border-radius: 4px;
    background: var(--paper);
    color: var(--fg);
  }
  input:focus { outline: 2px solid var(--accent-dim); outline-offset: 1px; }

  /* Verification status pills */
  .pill {
    display: inline-block;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 10px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
  }
  .pill-ok { background: #dfeee5; color: #2c6044; }
  .pill-dim { background: var(--code); color: var(--muted); }
  .pill-warn { background: #f5e3df; color: var(--accent); }

  footer.site {
    max-width: 720px;
    margin: 32px auto 0;
    padding: 16px 24px 40px;
    border-top: 1px solid var(--line);
    font-size: 13px;
    color: var(--muted);
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
`;

const DEFAULT_DESCRIPTION =
  'AFAuth trust attestor — links your account to an agent identity so services can recognise the human behind the agent.';

function baseUrl(): string {
  return (process.env.PUBLIC_BASE_URL ?? 'https://trust.afauth.org').replace(/\/$/, '');
}

export interface LayoutOpts {
  title: string;
  body: HtmlEscapedString | Promise<HtmlEscapedString>;
  description?: string;
  path?: string;
}

export function layout(opts: LayoutOpts): HtmlEscapedString | Promise<HtmlEscapedString> {
  const description = opts.description ?? DEFAULT_DESCRIPTION;
  const canonical = `${baseUrl()}${opts.path ?? ''}`;
  return html`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${opts.title}</title>
<meta name="description" content="${description}">
<link rel="canonical" href="${canonical}">
<meta property="og:type" content="website">
<meta property="og:site_name" content="trust.afauth.org">
<meta property="og:title" content="${opts.title}">
<meta property="og:description" content="${description}">
<meta property="og:url" content="${canonical}">
<link rel="icon" type="image/svg+xml" href="https://afauth.org/favicon.svg">
<style>${raw(STYLE)}</style>
</head>
<body>
<header class="site"><nav>
  <strong>trust.afauth.org</strong>
  <a href="/account">Account</a>
  <span class="spacer"></span>
  <a href="https://afauth.org" rel="noopener">afauth.org &#8599;</a>
  <a href="https://github.com/AFAuthHQ/spec/blob/main/proposals/0006-afauth-trust-attestor.md" target="_blank" rel="noopener">AFAP-0006 &#8599;</a>
</nav></header>
<main>${opts.body}</main>
<footer class="site">
  Operated by afauth.org per
  <a href="https://github.com/AFAuthHQ/spec/blob/main/proposals/0006-afauth-trust-attestor.md" target="_blank" rel="noopener">AFAP-0006</a>.
  No PII in attestation claims.
</footer>
</body>
</html>`;
}
