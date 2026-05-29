/**
 * Canonical form for an email address used as the durable identity
 * join key across every sign-in method (magic-link, Google OAuth).
 *
 * AFAP-0006 §7.7.1 defines the email match relation as case-insensitive
 * equality of the local-part and domain *after Unicode NFKC
 * normalization* (RFC 5321 §2.4). Every place that stores, looks up, or
 * compares an email MUST route through this one function so the same
 * person always resolves to the same `humans.id` — and therefore the
 * same `sub_h` (§10.4.2). The prior behaviour (`.toLowerCase()` only)
 * would split the same mailbox supplied in different Unicode
 * compatibility forms into two principals.
 *
 * Order follows §7.7.1 literally: NFKC normalize, then case-insensitive
 * (lowercase). `trim()` guards against stray surrounding whitespace from
 * form input. NFKC and lowercasing are each idempotent, so for the
 * ASCII/practical email inputs this service sees,
 * `canonicalizeEmail(canonicalizeEmail(x)) === canonicalizeEmail(x)` —
 * the function is safe to apply at more than one layer (the store
 * chokepoint and the OAuth boundary) without drift.
 *
 * NOT canonicalized: provider-specific aliasing (Gmail dots, `+tags`).
 * §7.7.1 deliberately leaves those distinct, so `a.b@gmail.com` and
 * `ab@gmail.com` remain different principals here.
 */
export function canonicalizeEmail(raw: string): string {
  return raw.trim().normalize('NFKC').toLowerCase();
}
