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

  it('is invariant across agent key rotation and same-human rebind (§10.4.2, §10.5.1)', () => {
    // sub_h takes no agent DID, binding id, or verification key as input —
    // it is a pure function of (principalId, aud, K). So a rotated key
    // re-linked to the same human, and a revoke-then-rebind to the same
    // human, both produce the SAME sub_h at a given service.
    const human = 'human-uuid-1';
    const aud = 'did:web:service-a.example';
    const beforeRotation = deriveSubH(human, aud, KEY);
    const afterRotation = deriveSubH(human, aud, KEY); // agent re-linked under a new DID, same human
    const afterRebind = deriveSubH(human, aud, KEY); // revoke + rebind, same human
    expect(afterRotation).toBe(beforeRotation);
    expect(afterRebind).toBe(beforeRotation);
  });

  it('matches a pinned known-answer (cross-version wire stability; breaks if inputs change)', () => {
    // Golden vector: any change to the derivation inputs — e.g. adding the
    // agent DID to the HMAC message — changes every human's sub_h at every
    // service and breaks §10.4.2 stability "across time". This pins it.
    const v = deriveSubH('human-uuid-1', 'did:web:service-a.example', KEY);
    expect(v).toBe('YViiIn0-69vg0ECqpntGain7FOx5u09F4m04E8wJrOo');
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
