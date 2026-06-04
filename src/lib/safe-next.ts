/**
 * Validates a post-authentication redirect target. Only same-site
 * relative paths are allowed: an absolute URL or a protocol-relative
 * `//host/...` is an open-redirect (phishing pivot), and an over-long
 * value is rejected too. Returns the safe path, or undefined if the
 * caller should fall back to a default.
 */
export function safeNext(next: string | undefined | null): string | undefined {
  if (!next) return undefined;
  if (!next.startsWith('/') || next.startsWith('//')) return undefined;
  if (next.length > 200) return undefined;
  return next;
}
