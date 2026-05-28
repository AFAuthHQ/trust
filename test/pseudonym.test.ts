import { describe, expect, it } from 'vitest';
import './helpers.js'; // setTestEnv side-effect for getConfig()
import { deriveSubH, pseudonymKeyBytes } from '../src/lib/pseudonym.js';

const KEY = Buffer.alloc(32, 0xcd);
const ALT_KEY = Buffer.alloc(32, 0x33);

describe('deriveSubH — AFAP-0006 §10.4 pairwise human pseudonym', () => {
  it('is stable for the same (principal, aud) across calls', () => {
    const a = deriveSubH('human-uuid-1', 'did:web:service-a.example', KEY);
    const b = deriveSubH('human-uuid-1', 'did:web:service-a.example', KEY);
    expect(a).toBe(b);
  });

  it('is pairwise — different aud → different sub_h for the same human', () => {
    const a = deriveSubH('human-uuid-1', 'did:web:service-a.example', KEY);
    const b = deriveSubH('human-uuid-1', 'did:web:service-b.example', KEY);
    expect(a).not.toBe(b);
  });

  it('is per-human — different principal → different sub_h at the same aud', () => {
    const a = deriveSubH('human-uuid-1', 'did:web:service-a.example', KEY);
    const b = deriveSubH('human-uuid-2', 'did:web:service-a.example', KEY);
    expect(a).not.toBe(b);
  });

  it('differs when K_pseudonym changes (deny correlation across attestor secrets)', () => {
    const a = deriveSubH('human-uuid-1', 'did:web:service-a.example', KEY);
    const b = deriveSubH('human-uuid-1', 'did:web:service-a.example', ALT_KEY);
    expect(a).not.toBe(b);
  });

  it('encodes as base64url within the spec [22,86] band, with no padding', () => {
    const v = deriveSubH('human-uuid-1', 'did:web:service-a.example', KEY);
    expect(v).toMatch(/^[A-Za-z0-9_-]{22,86}$/);
    expect(v).not.toContain('=');
    expect(v).not.toContain('+');
    expect(v).not.toContain('/');
  });

  it('produces 43-char output (HMAC-SHA256 → 32 bytes → base64url)', () => {
    const v = deriveSubH('any', 'any', KEY);
    expect(v).toHaveLength(43);
  });
});

describe('pseudonymKeyBytes', () => {
  it('returns 32 bytes (env-fixed test key set in helpers.ts)', () => {
    const k = pseudonymKeyBytes();
    expect(k.length).toBe(32);
  });
});
