import { randomUUID } from 'node:crypto';
import { canonicalizeEmail } from '../email.js';
import { TrustError } from '../errors.js';
import type {
  BindingRecord,
  CreateBindingInput,
  CreateHumanInput,
  CreateLinkRequestInput,
  HumanRecord,
  InsertSigningKeyInput,
  LinkRequestRecord,
  MagicLinkRecord,
  SessionRecord,
  SigningKeyRecord,
  Store,
  TokenLogEntry,
  VerificationRecord,
} from './index.js';
import type { VerificationMethod } from '../schemas.js';

/**
 * In-memory Store for tests and the optional `pnpm preview` mode.
 * No durability, no concurrency safety — exists solely to keep the
 * route tests independent of Postgres.
 */
export class MemoryStore implements Store {
  private humans = new Map<string, HumanRecord>();
  private verifications: VerificationRecord[] = [];
  private sessions = new Map<string, SessionRecord>();
  private magicLinks = new Map<string, MagicLinkRecord>();
  private linkRequests = new Map<string, LinkRequestRecord>();
  private bindings = new Map<string, BindingRecord>();
  private signingKeys = new Map<string, SigningKeyRecord>();
  private tokenLog: Array<TokenLogEntry & { issued_at: Date }> = [];

  // Strictly monotonic createdAt for signing keys. Date.now() has
  // 1ms resolution; two inserts in the same ms otherwise tie, which
  // would make getActive()'s tiebreak non-deterministic. Postgres'
  // now() has microsecond resolution and doesn't need this.
  private signingKeyInsertCounter = 0;

  async init(): Promise<void> {}
  async close(): Promise<void> {}

  // Humans
  async getHumanByEmail(email: string) {
    const norm = canonicalizeEmail(email);
    for (const h of this.humans.values()) {
      if (h.primary_email === norm) return h;
    }
    return null;
  }
  async getHumanById(id: string) {
    return this.humans.get(id) ?? null;
  }
  async upsertHuman(input: CreateHumanInput) {
    const existing = await this.getHumanByEmail(input.primary_email);
    if (existing) return existing;
    const h: HumanRecord = {
      id: randomUUID(),
      primary_email: canonicalizeEmail(input.primary_email),
      created_at: new Date(),
      disabled_at: null,
    };
    this.humans.set(h.id, h);
    return h;
  }

  // Verifications
  async recordVerification(
    human_id: string,
    method: VerificationMethod,
    provider: string,
    external_subject?: string,
  ) {
    // Enforce the partial unique index: (provider, external_subject)
    // must point at exactly one human when subject is non-null.
    if (external_subject) {
      const conflict = this.verifications.find(
        (v) =>
          v.provider === provider &&
          v.external_subject === external_subject &&
          v.human_id !== human_id,
      );
      if (conflict) {
        throw new Error(
          `external subject already linked to a different human (provider=${provider})`,
        );
      }
    }
    const existing = this.verifications.find(
      (v) => v.human_id === human_id && v.method === method && v.provider === provider,
    );
    if (existing) {
      existing.verified_at = new Date();
      existing.revoked_at = null;
      if (external_subject) existing.external_subject = external_subject;
      return existing;
    }
    const v: VerificationRecord = {
      id: randomUUID(),
      human_id,
      method,
      provider,
      external_subject: external_subject ?? null,
      verified_at: new Date(),
      revoked_at: null,
    };
    this.verifications.push(v);
    return v;
  }
  async listVerifications(human_id: string) {
    return this.verifications.filter(
      (v) => v.human_id === human_id && v.revoked_at === null,
    );
  }
  async findVerificationByExternalSubject(provider: string, external_subject: string) {
    return (
      this.verifications.find(
        (v) =>
          v.provider === provider &&
          v.external_subject === external_subject &&
          v.revoked_at === null,
      ) ?? null
    );
  }
  async revokeVerification(human_id: string, method: VerificationMethod, provider: string) {
    const v = this.verifications.find(
      (v) =>
        v.human_id === human_id &&
        v.method === method &&
        v.provider === provider &&
        v.revoked_at === null,
    );
    if (v) v.revoked_at = new Date();
  }

  // Sessions
  async createSession(human_id: string, token_hash: string, expires_at: Date) {
    const s: SessionRecord = {
      id: randomUUID(),
      human_id,
      token_hash,
      created_at: new Date(),
      expires_at,
    };
    this.sessions.set(s.id, s);
    return s;
  }
  async getSessionByTokenHash(token_hash: string) {
    for (const s of this.sessions.values()) {
      if (s.token_hash === token_hash && s.expires_at.getTime() > Date.now()) {
        return s;
      }
    }
    return null;
  }
  async deleteSession(id: string) {
    this.sessions.delete(id);
  }

  // Magic links
  async createMagicLink(
    email: string,
    token_hash: string,
    expires_at: Date,
    next_path?: string,
  ) {
    const m: MagicLinkRecord = {
      id: randomUUID(),
      email: canonicalizeEmail(email),
      token_hash,
      expires_at,
      consumed_at: null,
      next_path: next_path ?? null,
    };
    this.magicLinks.set(m.id, m);
    return m;
  }
  async peekMagicLink(token_hash: string) {
    for (const m of this.magicLinks.values()) {
      if (
        m.token_hash === token_hash &&
        m.consumed_at === null &&
        m.expires_at.getTime() > Date.now()
      ) {
        return m;
      }
    }
    return null;
  }

  async consumeMagicLink(token_hash: string) {
    for (const m of this.magicLinks.values()) {
      if (
        m.token_hash === token_hash &&
        m.consumed_at === null &&
        m.expires_at.getTime() > Date.now()
      ) {
        m.consumed_at = new Date();
        return m;
      }
    }
    return null;
  }

  // Link requests
  async createLinkRequest(input: CreateLinkRequestInput) {
    const lr: LinkRequestRecord = {
      id: randomUUID(),
      agent_did: input.agent_did,
      agent_label: input.agent_label ?? null,
      agent_pubkey_b64: input.agent_pubkey_b64,
      state: 'pending',
      human_id: null,
      binding_id: null,
      created_at: new Date(),
      expires_at: input.expires_at,
      confirmed_at: null,
      callback_url: input.callback_url ?? null,
    };
    this.linkRequests.set(lr.id, lr);
    return lr;
  }
  async getLinkRequest(id: string) {
    return this.linkRequests.get(id) ?? null;
  }
  async confirmLinkRequest(id: string, human_id: string, binding_id: string) {
    const lr = this.linkRequests.get(id);
    if (!lr || lr.state !== 'pending' || lr.expires_at.getTime() < Date.now()) {
      return null;
    }
    lr.state = 'confirmed';
    lr.human_id = human_id;
    lr.binding_id = binding_id;
    lr.confirmed_at = new Date();
    return lr;
  }

  // Bindings
  async createBinding(input: CreateBindingInput) {
    // §10.5 — at most one active binding per agent_did. If one
    // exists for a different human, reject; if for the same human,
    // refresh in place (re-link to rotate the token).
    const existingActive = await this.findActiveBindingByAgentDid(input.agent_did);
    if (existingActive && existingActive.human_id !== input.human_id) {
      throw TrustError.agentAlreadyBound();
    }
    if (existingActive && existingActive.human_id === input.human_id) {
      existingActive.agent_label = input.agent_label ?? null;
      existingActive.agent_pubkey_b64 = input.agent_pubkey_b64;
      existingActive.binding_token_hash = input.binding_token_hash;
      existingActive.expires_at = input.expires_at;
      return existingActive;
    }
    const b: BindingRecord = {
      id: randomUUID(),
      human_id: input.human_id,
      agent_did: input.agent_did,
      agent_label: input.agent_label ?? null,
      agent_pubkey_b64: input.agent_pubkey_b64,
      binding_token_hash: input.binding_token_hash,
      created_at: new Date(),
      expires_at: input.expires_at,
      revoked_at: null,
      last_used_at: null,
    };
    this.bindings.set(b.id, b);
    return b;
  }
  async getBindingByTokenHash(token_hash: string) {
    for (const b of this.bindings.values()) {
      if (b.binding_token_hash === token_hash) return b;
    }
    return null;
  }
  async getBindingById(id: string) {
    return this.bindings.get(id) ?? null;
  }
  async findActiveBindingByAgentDid(agent_did: string) {
    for (const b of this.bindings.values()) {
      if (b.agent_did === agent_did && b.revoked_at === null) return b;
    }
    return null;
  }
  async listBindingsByHuman(human_id: string) {
    return [...this.bindings.values()]
      .filter((b) => b.human_id === human_id)
      .sort((a, b) => b.created_at.getTime() - a.created_at.getTime());
  }
  async revokeBinding(id: string, human_id: string) {
    const b = this.bindings.get(id);
    if (!b || b.human_id !== human_id || b.revoked_at) return null;
    b.revoked_at = new Date();
    return b;
  }
  async touchBindingLastUsed(id: string, when: Date) {
    const b = this.bindings.get(id);
    if (b) b.last_used_at = when;
  }

  // Signing keys
  async listActiveSigningKeys() {
    return [...this.signingKeys.values()]
      .filter((k) => k.retiredAt === null)
      .sort((a, b) => b.activeFrom.getTime() - a.activeFrom.getTime());
  }
  async retireSigningKey(kid: string) {
    const k = this.signingKeys.get(kid);
    if (k && k.retiredAt === null) k.retiredAt = new Date();
  }

  async insertSigningKey(input: InsertSigningKeyInput) {
    const k: SigningKeyRecord = {
      kid: input.kid,
      alg: input.alg,
      publicJwk: input.publicJwk,
      privateJwkEnc: input.privateJwkEnc,
      privateJwkIv: input.privateJwkIv,
      createdAt: new Date(Date.now() + this.signingKeyInsertCounter++),
      activeFrom: input.activeFrom,
      retiredAt: null,
    };
    this.signingKeys.set(k.kid, k);
    return k;
  }

  // Audit
  async logIssuedToken(entry: TokenLogEntry) {
    this.tokenLog.push({ ...entry, issued_at: new Date() });
  }
  async recentTokensByHuman(human_id: string, limit: number) {
    return this.tokenLog
      .filter((t) => {
        const b = this.bindings.get(t.binding_id);
        return b?.human_id === human_id;
      })
      .map((t) => {
        const b = this.bindings.get(t.binding_id)!;
        return {
          binding_id: t.binding_id,
          agent_did: b.agent_did,
          service_did: t.service_did,
          verification: t.verification,
          issued_at: t.issued_at,
        };
      })
      .sort((a, b) => b.issued_at.getTime() - a.issued_at.getTime())
      .slice(0, limit);
  }
}
