import { Hono } from 'hono';

function baseUrl(): string {
  return (process.env.PUBLIC_BASE_URL ?? 'https://trust.afauth.org').replace(/\/$/, '');
}

// Bodies are built per-request (not snapshotted into module-level consts)
// so the base URL always reflects the live PUBLIC_BASE_URL, regardless of
// import order.
function robotsTxt(): string {
  return `# trust.afauth.org — AFAuth trust attestor
#
# This is the canonical §10 trust attestor: an agent links to a human
# once, then carries short-lived, PII-free attestations that
# spam-resistant services require. Crawlers — including LLM training
# and search bots — are explicitly welcome on the public pages.

# Content Signals (https://contentsignals.org): AFAuth welcomes agents —
# every AI use is permitted. Search indexing, AI input (RAG/grounding),
# and model training are all explicitly allowed; blocking the agents this
# attestor exists to serve would be ironic.
User-agent: *
Content-Signal: search=yes, ai-input=yes, ai-train=yes
Allow: /
Disallow: /admin/
Disallow: /auth/

User-agent: GPTBot
Allow: /

User-agent: ChatGPT-User
Allow: /

User-agent: OAI-SearchBot
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: Claude-Web
Allow: /

User-agent: anthropic-ai
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: Perplexity-User
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: CCBot
Allow: /

User-agent: Bytespider
Allow: /

User-agent: Amazonbot
Allow: /

User-agent: Applebot-Extended
Allow: /

Sitemap: ${baseUrl()}/sitemap.xml
`;
}

function llmsTxt(): string {
  return `# trust.afauth.org — AFAuth trust attestor

> The canonical §10 trust attestor for AFAuth (Agent-First Auth). An AI
> agent links to a human here exactly once; the attestor then mints
> short-lived, audience-bound, PII-free attestation JWTs that
> spam-resistant services require at signup. No personal data ever
> appears in an attestation claim.

## Sibling sites (AFAuth constellation)

AFAuth is documented across coordinated properties. This site is the
**trust plane** — where an agent earns a human-backed signal. For the
protocol itself and developer docs, follow the links below.

- **Protocol home**: https://afauth.org/llms.txt — what AFAuth is, the manifesto, install paths.
- **Documentation**: https://docs.afauth.org/llms.txt — quickstarts, SDK reference, the §-by-§ spec walkthrough.
- **Service directory**: https://registry.afauth.org/llms.txt — opt-in registry of AFAuth-enabled services.
- **Trust attestor** (this site): ${baseUrl()}/llms.txt — link an agent to a human, mint PII-free attestations.

## What this site does

This is the reference implementation of the §10 trust-attestor role
defined in [AFAP-0006](https://github.com/AFAuthHQ/spec/blob/main/proposals/0006-afauth-trust-attestor.md).
It exists so a service can demand "this agent is backed by a real
human" without ever learning who that human is.

## How an agent earns an attestation

1. **Link once.** The human opens the link page (${baseUrl()}/link),
   authenticates (e.g. Google), and approves the binding between their
   identity and the agent's \`did:key\`. This happens a single time per
   agent — the \`afauth trust link\` CLI command opens this page.
2. **Mint per service.** When a service's \`/.well-known/afauth\`
   discovery document lists this attestor among the attestors it
   accepts, the agent requests a fresh attestation token scoped to that
   service (audience-bound) and short-lived.
3. **Present at signup.** The agent sends the token alongside its
   signed signup request. The service verifies it against this
   attestor's JWKS and accepts the account — with zero PII transferred.

Attestation claims are deliberately minimal and contain **no personal
information**: no name, no email, no profile — only a stable,
non-reversible binding reference, an audience, and an expiry.

## Endpoints

- [Link an agent](${baseUrl()}/link) — human-facing page to authorise a binding.
- [Account](${baseUrl()}/account) — manage your bindings after linking.
- [JWKS](${baseUrl()}/.well-known/jwks.json) — public keys services use to verify attestation tokens.
- [Operator commitment](${baseUrl()}/operator) — who runs this attestor and what they may / may not do.
- [Policy](${baseUrl()}/policy) — attestation and moderation policy.
- [AFAP-0006](https://github.com/AFAuthHQ/spec/blob/main/proposals/0006-afauth-trust-attestor.md) — normative attestor design.

## Contact

- GitHub: https://github.com/AFAuthHQ/trust
- Security: ${baseUrl()}/.well-known/security.txt
- License: Apache-2.0 (code), CC-BY-4.0 (spec)
`;
}

const SITEMAP_PATHS = ['/', '/operator', '/policy', '/link'];

export function createSeoRoutes(): Hono {
  const r = new Hono();

  r.get('/robots.txt', (c) => {
    c.header('content-type', 'text/plain; charset=utf-8');
    // Short cache: robots.txt carries discovery directives (Content-Signal,
    // sitemap pointer) that gate agent-readiness. A long CDN/proxy cache
    // makes edits propagate slowly — keep it brief so changes go live fast.
    c.header('cache-control', 'public, max-age=300');
    return c.body(robotsTxt());
  });

  r.get('/llms.txt', (c) => {
    c.header('content-type', 'text/markdown; charset=utf-8');
    c.header('cache-control', 'public, max-age=3600');
    return c.body(llmsTxt());
  });

  r.get('/sitemap.xml', (c) => {
    const base = baseUrl();
    const body =
      `<?xml version="1.0" encoding="UTF-8"?>\n` +
      `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n` +
      SITEMAP_PATHS.map(
        (p) => `  <url>\n    <loc>${escapeXml(base + p)}</loc>\n  </url>`,
      ).join('\n') +
      `\n</urlset>\n`;
    c.header('content-type', 'application/xml; charset=utf-8');
    c.header('cache-control', 'public, max-age=3600');
    return c.body(body);
  });

  r.get('/.well-known/security.txt', (c) => {
    // RFC 9116 §2.5.5: Expires is REQUIRED. Roll it one year out;
    // bump on each touch of this file.
    const expires = '2027-06-08T00:00:00.000Z';
    c.header('content-type', 'text/plain; charset=utf-8');
    return c.body(
      `Contact: mailto:[email protected]\n` +
        `Expires: ${expires}\n` +
        `Preferred-Languages: en\n` +
        `Canonical: ${baseUrl()}/.well-known/security.txt\n` +
        `Policy: https://github.com/AFAuthHQ/.github/blob/main/SECURITY.md\n`,
    );
  });

  return r;
}

function escapeXml(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}
