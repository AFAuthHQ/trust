/**
 * §5 (RFC 9421) request-signature verification for the trust attestor's
 * OWN endpoints — specifically the keyless `/v1/token` mint path (§3.1),
 * where the agent authenticates by signing the request with its account
 * key instead of presenting a bearer `binding_token`. The attestor is, in
 * effect, "just another AFAuth-verifying endpoint": it resolves the key
 * from `keyid` (a `did:key`, zero I/O), runs the §5.5 checks, and maps the
 * verified `keyid` to a binding.
 *
 * This is a self-contained port of the verification that @afauthhq/server
 * performs, kept dependency-free so the trust service deploys (Railway)
 * independently of an npm release. The canonical-input construction is
 * byte-identical to @afauthhq/core's `buildCanonicalInput`; `request-sig`'s
 * test pins it against the spec's published reference vector (§C.1/§C.2)
 * so any drift from core is caught.
 *
 * The §5.2 required-covered-component rule is enforced here from the start
 * (@method + @target-uri always; content-digest when a body is present) —
 * a verifier must never trust the signer to self-select which
 * security-critical inputs are bound.
 */
import { createHash, createPublicKey, verify as edVerify } from 'node:crypto';
import type Redis from 'ioredis';
import { decodeDidKey } from './did.js';
import { TrustError } from './errors.js';

type CoveredComponent = '@method' | '@target-uri' | 'content-digest';

interface SignatureParams {
  created: number;
  expires: number;
  nonce: string;
  keyid: string;
  alg: 'ed25519';
}

export interface AgentSignedRequest {
  method: string;
  /**
   * The canonical `@target-uri` the agent signed. The route reconstructs
   * this from `PUBLIC_BASE_URL` + the endpoint path rather than trusting
   * the observed request URL, so a TLS-terminating proxy (Railway) that
   * rewrites scheme/host can't break verification.
   */
  targetUri: string;
  signatureInput: string | null;
  signature: string | null;
  contentDigest: string | null;
  /** Raw request body bytes — RFC 9530 digest is defined over bytes. */
  body: Uint8Array;
}

export interface VerifyAgentRequestDeps {
  redis: Redis;
  /** Unix seconds. Defaults to `Date.now()/1000`. */
  now?: () => number;
  /** Default 60s — the §5.5 RECOMMENDED tolerance. */
  clockSkewSeconds?: number;
  /** Default 300s — the §5.2 ceiling on `expires - created`. */
  maxLifetimeSeconds?: number;
  /** Redis nonce namespace. Default `reqsig`. */
  noncePrefix?: string;
}

/**
 * Verifies an agent's §5-signed request and returns the verified `keyid`
 * (the agent account DID). Throws `TrustError` (401 `invalid_signature`,
 * or 400 `invalid_request` for a malformed `did:key` keyid) on any
 * failure. Maintains a Redis `(keyid, nonce)` replay set for the freshness
 * window.
 */
export async function verifyAgentRequestSignature(
  req: AgentSignedRequest,
  deps: VerifyAgentRequestDeps,
): Promise<{ keyid: string }> {
  const now = deps.now ?? (() => Math.floor(Date.now() / 1000));
  const clockSkew = deps.clockSkewSeconds ?? 60;
  const maxLifetime = deps.maxLifetimeSeconds ?? 300;
  const noncePrefix = deps.noncePrefix ?? 'reqsig';

  if (!req.signatureInput) throw TrustError.invalidSignature('missing Signature-Input header');
  if (!req.signature) throw TrustError.invalidSignature('missing Signature header');

  const { label, covered, params } = parseSignatureInput(req.signatureInput);
  const sigBytes = parseSignature(req.signature, label);

  // §5.2: content-digest MUST be covered when the body is non-empty.
  const hasBody = req.body.byteLength > 0;
  if (hasBody && !covered.includes('content-digest')) {
    throw TrustError.invalidSignature(
      'content-digest must be a covered component when the request has a body (§5.2)',
    );
  }

  // Time bounds (§5.6).
  if (params.expires <= params.created) {
    throw TrustError.invalidSignature('expires must be greater than created');
  }
  if (params.expires - params.created > maxLifetime) {
    throw TrustError.invalidSignature(`signature lifetime exceeds maximum (${maxLifetime}s)`);
  }
  const t = now();
  if (t < params.created - clockSkew) throw TrustError.invalidSignature('signature is future-dated');
  if (t > params.expires + clockSkew) throw TrustError.invalidSignature('signature has expired');

  // Content-Digest match.
  if (covered.includes('content-digest')) {
    if (!req.contentDigest) {
      throw TrustError.invalidSignature(
        'Content-Digest header missing but covered components include content-digest',
      );
    }
    if (req.contentDigest !== sha256ContentDigest(req.body)) {
      throw TrustError.invalidSignature('Content-Digest does not match SHA-256 of body');
    }
  }

  // Rebuild the canonical input and verify the Ed25519 signature.
  const canonical = buildCanonicalInput(
    req.method,
    req.targetUri,
    req.contentDigest ?? undefined,
    params,
    covered,
  );
  const rawPub = decodeDidKey(params.keyid); // throws invalid_request on a non-ed25519 did:key
  if (!ed25519Verify(canonical, sigBytes, rawPub)) {
    throw TrustError.invalidSignature('Ed25519 signature did not verify');
  }

  // Replay protection (§5.6) — checked AFTER signature verification so a
  // bad signature can't consume a legitimate (keyid, nonce) slot.
  const ttl = Math.max(params.expires - params.created + clockSkew, 1);
  const nonceKey = `${noncePrefix}:nonce:${params.keyid}:${params.nonce}`;
  const fresh = await deps.redis.set(nonceKey, '1', 'EX', ttl, 'NX');
  if (fresh === null) throw TrustError.invalidSignature('nonce has been seen before (replay)');

  return { keyid: params.keyid };
}

// ---------------------------------------------------------------------
// §5 parsing / canonicalisation — byte-identical to @afauthhq/core +
// @afauthhq/server. Drift is caught by request-sig.test.ts against the
// spec's reference vector.
// ---------------------------------------------------------------------

interface ParsedSignatureInput {
  label: string;
  covered: CoveredComponent[];
  params: SignatureParams;
}

function parseSignatureInput(header: string): ParsedSignatureInput {
  const match = /^(\w+)=\(([^)]*)\)\s*(?:;\s*(.*))?$/.exec(header.trim());
  if (!match) throw TrustError.invalidSignature('malformed Signature-Input header');
  const [, label, componentsStr, paramsStr = ''] = match;

  const covered: CoveredComponent[] = [];
  for (const raw of componentsStr!.split(/\s+/).filter(Boolean)) {
    const c = unquote(raw);
    if (c === '@method' || c === '@target-uri' || c === 'content-digest') {
      covered.push(c);
    } else {
      throw TrustError.invalidSignature(`unsupported covered component: ${c}`);
    }
  }

  // §5.2 / §5.5 step 1: @method and @target-uri are always required.
  for (const required of ['@method', '@target-uri'] as const) {
    if (!covered.includes(required)) {
      throw TrustError.invalidSignature(`missing required covered component: ${required} (§5.2)`);
    }
  }

  const partial: Partial<SignatureParams> = {};
  for (const part of paramsStr.split(';').map((p) => p.trim()).filter(Boolean)) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    const key = part.slice(0, eq).trim();
    const rawVal = part.slice(eq + 1).trim();
    if (key === 'created' || key === 'expires') {
      const n = Number(rawVal);
      if (!Number.isInteger(n)) throw TrustError.invalidSignature(`${key} must be an integer`);
      partial[key] = n;
    } else if (key === 'nonce') {
      partial.nonce = unquote(rawVal);
    } else if (key === 'keyid') {
      partial.keyid = unquote(rawVal);
    } else if (key === 'alg') {
      const v = unquote(rawVal);
      if (v !== 'ed25519') throw TrustError.invalidSignature(`unsupported alg: ${v}`);
      partial.alg = 'ed25519';
    }
  }
  for (const k of ['created', 'expires', 'nonce', 'keyid', 'alg'] as const) {
    if (partial[k] === undefined) {
      throw TrustError.invalidSignature(`missing signature param: ${k}`);
    }
  }
  return { label: label!, covered, params: partial as SignatureParams };
}

function parseSignature(header: string, label: string): Uint8Array {
  const re = new RegExp(`(?:^|,)\\s*${escapeRegExp(label)}=:([A-Za-z0-9+/=]+):`);
  const m = re.exec(header);
  if (!m) throw TrustError.invalidSignature(`Signature header missing label "${label}"`);
  return new Uint8Array(Buffer.from(m[1]!, 'base64'));
}

/**
 * Byte-identical to @afauthhq/core `buildCanonicalInput`. The covered
 * components are emitted in the order they appear in `Signature-Input`,
 * each on its own line, followed by the `@signature-params` line; joined
 * with `\n`, no trailing newline.
 */
function buildCanonicalInput(
  method: string,
  targetUri: string,
  contentDigest: string | undefined,
  params: SignatureParams,
  covered: readonly CoveredComponent[],
): string {
  const lines: string[] = [];
  for (const component of covered) {
    if (component === '@method') {
      lines.push(`"@method": ${method}`);
    } else if (component === '@target-uri') {
      lines.push(`"@target-uri": ${targetUri}`);
    } else if (component === 'content-digest') {
      if (contentDigest === undefined) {
        throw TrustError.invalidSignature('covered components include content-digest but none present');
      }
      lines.push(`"content-digest": ${contentDigest}`);
    }
  }
  const componentList = covered.map((c) => `"${c}"`).join(' ');
  const paramStr =
    `created=${params.created};` +
    `expires=${params.expires};` +
    `nonce="${params.nonce}";` +
    `keyid="${params.keyid}";` +
    `alg="${params.alg}"`;
  lines.push(`"@signature-params": (${componentList});${paramStr}`);
  return lines.join('\n');
}

/** `sha-256=:<base64>:` over the raw body bytes (RFC 9530 §2). */
function sha256ContentDigest(body: Uint8Array): string {
  return `sha-256=:${createHash('sha256').update(body).digest('base64')}:`;
}

function ed25519Verify(canonical: string, sig: Uint8Array, rawPub: Uint8Array): boolean {
  if (sig.length !== 64 || rawPub.length !== 32) return false;
  try {
    const key = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: toBase64Url(rawPub) },
      format: 'jwk',
    });
    return edVerify(null, new TextEncoder().encode(canonical), key, sig);
  } catch {
    return false;
  }
}

function unquote(s: string): string {
  return s.startsWith('"') && s.endsWith('"') && s.length >= 2 ? s.slice(1, -1) : s;
}

function escapeRegExp(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function toBase64Url(buf: Uint8Array): string {
  return Buffer.from(buf).toString('base64').replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_');
}
