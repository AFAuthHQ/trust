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
    border-bottom: 1px solid rgba(20, 16, 8, 0.10);
    background: rgba(245, 239, 228, 0.78);
    backdrop-filter: blur(16px) saturate(120%);
    -webkit-backdrop-filter: blur(16px) saturate(120%);
    position: sticky;
    top: 0;
    z-index: 30;
  }
  header.site nav {
    max-width: 1248px;
    margin: 0 auto;
    padding: 14px 24px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }
  header.site .brand {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    color: var(--fg);
    text-decoration: none;
  }
  header.site .brand svg { display: block; height: 24px; width: 24px; }
  header.site .brand .wordmark {
    font-family: 'IBM Plex Sans', ui-sans-serif, system-ui, -apple-system, sans-serif;
    font-size: 17px;
    font-weight: 600;
    letter-spacing: -0.015em;
    color: var(--fg);
  }
  header.site .brand .surface {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.18em;
    color: var(--muted);
    padding-left: 10px;
    margin-left: 4px;
    border-left: 1px solid rgba(20, 16, 8, 0.18);
  }
  header.site .brand:hover .wordmark,
  header.site .brand:hover .surface { color: var(--accent); }
  header.site .links {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: 0.18em;
  }
  header.site .links a {
    padding: 6px 12px;
    color: #3F362D;
    text-decoration: none;
  }
  header.site .links a:hover { color: var(--accent); }
  header.site .links a.ext { display: inline-flex; align-items: center; gap: 6px; }
  header.site .links a.ext svg { height: 14px; width: 14px; }
  @media (max-width: 640px) {
    header.site .links a.hide-sm { display: none; }
    header.site .brand .surface { display: none; }
  }
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
<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<style>${raw(STYLE)}</style>
</head>
<body>
<header class="site"><nav>
  <a class="brand" href="/" aria-label="AFAuth trust attestor — home">
    <svg viewBox="0 0 64 64" aria-hidden="true">
      <path d="M14 46 L32 14 L50 46 Z" fill="none" stroke="#B83227" stroke-width="5" stroke-linejoin="round"/>
      <circle cx="32" cy="36" r="3.5" fill="#B83227"/>
    </svg>
    <span class="wordmark">AFAuth</span>
    <span class="surface">Trust</span>
  </a>
  <div class="links">
    <a class="hide-sm" href="/account">Account</a>
    <a class="hide-sm" href="/operator">Operator</a>
    <a class="hide-sm" href="/policy">Policy</a>
    <a href="https://afauth.org" rel="noopener">afauth.org</a>
    <a class="ext" href="https://github.com/AFAuthHQ" target="_blank" rel="noopener" aria-label="AFAuth on GitHub">
      <svg viewBox="0 0 16 16" fill="currentColor" aria-hidden="true">
        <path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z"/>
      </svg>
      <span class="hide-sm">GitHub</span>
    </a>
  </div>
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
