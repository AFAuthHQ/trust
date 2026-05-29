import { describe, expect, it } from 'vitest';
import { canonicalizeEmail } from '../src/lib/email.js';

describe('canonicalizeEmail — AFAP-0006 §7.7.1 email match relation', () => {
  it('trims surrounding whitespace and lowercases local-part + domain', () => {
    expect(canonicalizeEmail('  Alice@Example.COM  ')).toBe('alice@example.com');
  });

  it('leaves an already-canonical ASCII address unchanged', () => {
    expect(canonicalizeEmail('alice@example.com')).toBe('alice@example.com');
  });

  it('NFKC-normalizes compatibility characters before casefolding', () => {
    expect(canonicalizeEmail('ＡＢＣ@example.com')).toBe('abc@example.com'); // fullwidth Latin
    expect(canonicalizeEmail('ﬁ@example.com')).toBe('fi@example.com'); // U+FB01 ligature
    expect(canonicalizeEmail('user＠example.com')).toBe('user@example.com'); // fullwidth @ (U+FF20)
  });

  it('converges distinct Unicode forms of the same mailbox to one key', () => {
    // The split vector this closes: the same person via two sign-in
    // methods, one supplying a compatibility form, must resolve to the
    // same humans.id (and thus the same sub_h, §10.4.2).
    expect(canonicalizeEmail('ＡＢＣ@example.com')).toBe(canonicalizeEmail('abc@example.com'));
  });

  it('is idempotent — safe to apply at both the store and OAuth layers', () => {
    for (const e of ['  Alice@Example.COM  ', 'ＡＢＣ@example.com', 'ﬁ@example.com']) {
      const once = canonicalizeEmail(e);
      expect(canonicalizeEmail(once)).toBe(once);
    }
  });

  it('does NOT collapse provider aliasing (Gmail dots / +tags stay distinct, §7.7.1)', () => {
    expect(canonicalizeEmail('a.b@gmail.com')).not.toBe(canonicalizeEmail('ab@gmail.com'));
    expect(canonicalizeEmail('a+x@gmail.com')).not.toBe(canonicalizeEmail('a@gmail.com'));
  });
});
