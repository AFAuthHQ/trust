import type { JWK } from 'jose';
import type { VerificationMethod } from '../schemas.js';

export interface HumanRecord {
  id: string;
  primary_email: string;
  created_at: Date;
  paused_at: Date | null;
}

export interface VerificationRecord {
  id: string;
  human_id: string;
  method: VerificationMethod;
  provider: string;
  /**
   * Stable upstream identifier (e.g. Google ID-token "sub" claim) when
   * the verification is an external OAuth identity; null for
   * provider-less methods like 'email'. Unique per (provider, subject)
   * to stop a second human claiming an already-linked OAuth account.
   */
  external_subject: string | null;
  verified_at: Date;
  revoked_at: Date | null;
}

export interface SessionRecord {
  id: string;
  human_id: string;
  token_hash: string;
  created_at: Date;
  expires_at: Date;
}

export interface MagicLinkRecord {
  id: string;
  email: string;
  token_hash: string;
  expires_at: Date;
  consumed_at: Date | null;
  next_path: string | null;
}

export interface LinkRequestRecord {
  id: string;
  agent_did: string;
  agent_label: string | null;
  agent_pubkey_b64: string;
  state: 'pending' | 'confirmed' | 'expired' | 'canceled';
  human_id: string | null;
  binding_id: string | null;
  created_at: Date;
  expires_at: Date;
  confirmed_at: Date | null;
  callback_url: string | null;
}

export interface BindingRecord {
  id: string;
  human_id: string;
  agent_did: string;
  agent_label: string | null;
  agent_pubkey_b64: string;
  created_at: Date;
  expires_at: Date;
  revoked_at: Date | null;
  last_used_at: Date | null;
}

export interface ServiceSignupRecord {
  id: string;
  human_id: string;
  agent_did: string;
  service_did: string;
  first_seen: Date;
  last_seen: Date;
  /** Non-null once the owner has revoked minting for this (agent DID, service) pair. */
  revoked_at: Date | null;
}

export interface SigningKeyRecord {
  kid: string;
  alg: string;
  publicJwk: JWK;
  /** AES-256-GCM ciphertext of the private JWK + 16-byte auth tag. */
  privateJwkEnc: Buffer;
  /** 96-bit GCM IV. */
  privateJwkIv: Buffer;
  /** Insertion timestamp; tiebreaks getActive() when two keys share activeFrom. */
  createdAt: Date;
  activeFrom: Date;
  retiredAt: Date | null;
}

export interface CreateHumanInput {
  primary_email: string;
}

export interface CreateBindingInput {
  human_id: string;
  agent_did: string;
  agent_label?: string;
  agent_pubkey_b64: string;
  expires_at: Date;
}

export interface CreateLinkRequestInput {
  agent_did: string;
  agent_label?: string;
  agent_pubkey_b64: string;
  expires_at: Date;
  callback_url?: string;
}

export interface InsertSigningKeyInput {
  kid: string;
  alg: string;
  publicJwk: JWK;
  privateJwkEnc: Buffer;
  privateJwkIv: Buffer;
  activeFrom: Date;
}

export interface TokenLogEntry {
  binding_id: string;
  service_did: string;
  verification: VerificationMethod;
  kid: string;
  expires_at: Date;
}

export interface Store {
  init(): Promise<void>;
  close(): Promise<void>;

  // Humans
  getHumanByEmail(email: string): Promise<HumanRecord | null>;
  getHumanById(id: string): Promise<HumanRecord | null>;
  upsertHuman(input: CreateHumanInput): Promise<HumanRecord>;
  /**
   * Set or clear the human-level pause flag (owner kill-switch).
   * When set, POST /v1/token refuses to mint for any of this human's
   * bindings (§8.4). Returns the updated record, or null if no such
   * human (mirrors revokeBinding's null-on-miss contract).
   */
  setHumanPaused(human_id: string, paused: boolean): Promise<HumanRecord | null>;

  // Verifications
  recordVerification(
    human_id: string,
    method: VerificationMethod,
    provider: string,
    external_subject?: string,
  ): Promise<VerificationRecord>;
  listVerifications(human_id: string): Promise<VerificationRecord[]>;
  /**
   * Look up a verification by its upstream identity. Used during OAuth
   * callback to decide whether a Google account already maps to a
   * known human (sign-in) or is fresh (sign-up / link). Ignores the
   * email — `sub` is the only stable identifier.
   */
  findVerificationByExternalSubject(
    provider: string,
    external_subject: string,
  ): Promise<VerificationRecord | null>;
  revokeVerification(
    human_id: string,
    method: VerificationMethod,
    provider: string,
  ): Promise<void>;

  // Sessions
  createSession(human_id: string, token_hash: string, expires_at: Date): Promise<SessionRecord>;
  getSessionByTokenHash(token_hash: string): Promise<SessionRecord | null>;
  deleteSession(id: string): Promise<void>;

  // Magic links
  createMagicLink(
    email: string,
    token_hash: string,
    expires_at: Date,
    next_path?: string,
  ): Promise<MagicLinkRecord>;
  /**
   * Look up a magic link by token hash WITHOUT consuming it. Returns
   * the record if it exists, is unconsumed, and not expired; null
   * otherwise. Used by GET /signin/callback to render the consent
   * page without burning the token (URL pre-fetchers like Microsoft
   * SafeLinks aggressively GET email links and would otherwise
   * invalidate the link before the human ever sees it).
   */
  peekMagicLink(token_hash: string): Promise<MagicLinkRecord | null>;
  consumeMagicLink(token_hash: string): Promise<MagicLinkRecord | null>;

  // Link requests
  createLinkRequest(input: CreateLinkRequestInput): Promise<LinkRequestRecord>;
  getLinkRequest(id: string): Promise<LinkRequestRecord | null>;
  confirmLinkRequest(
    id: string,
    human_id: string,
    binding_id: string,
  ): Promise<LinkRequestRecord | null>;

  // Bindings
  createBinding(input: CreateBindingInput): Promise<BindingRecord>;
  getBindingById(id: string): Promise<BindingRecord | null>;
  /**
   * AFAP-0006 §10.5 — returns the (at most one) active, unrevoked
   * binding for the agent DID, or null. Used by link-confirm to
   * reject co-binding attempts before they reach the unique-index
   * race in createBinding.
   */
  findActiveBindingByAgentDid(agent_did: string): Promise<BindingRecord | null>;
  /**
   * Most recent binding for the agent DID, ANY status (active, expired,
   * or revoked), or null. Used by the keyless `/v1/token` mint path
   * (§3.1): after `findActiveBindingByAgentDid` returns null, this lets
   * the route distinguish "the owner revoked this agent" (→
   * `binding_revoked`) from "this key was never linked" (→
   * `unauthorized`). Unlike `findLatestRevokedBindingByAgentDid` it is
   * NOT scoped to a human — the signed mint call resolves the human FROM
   * the binding, so it has none to pass.
   */
  findLatestBindingByAgentDid(agent_did: string): Promise<BindingRecord | null>;
  /**
   * Most recent REVOKED binding this human held for the agent DID, or
   * null. Used by /link to warn that re-linking re-enables a key the
   * owner previously revoked. Scoped to the human so one owner's
   * revocation history isn't disclosed to another.
   */
  findLatestRevokedBindingByAgentDid(
    agent_did: string,
    human_id: string,
  ): Promise<BindingRecord | null>;
  listBindingsByHuman(human_id: string): Promise<BindingRecord[]>;
  revokeBinding(id: string, human_id: string): Promise<BindingRecord | null>;
  /**
   * Records a successful mint: bumps `last_used_at` to `usedAt` and
   * re-arms `expires_at` to `expiresAt` (the binding inactivity window) in one
   * write. Called on every successful /v1/token mint.
   */
  recordBindingUse(id: string, usedAt: Date, expiresAt: Date): Promise<void>;

  // Service signups (connected-services ledger, §10.3.1 / §8.5)
  /**
   * Upsert the (agent DID, service) pair on a successful mint: insert with
   * first_seen on the first mint, bump last_seen on later ones. Owner-scoped
   * via human_id (the binding's human). Never revokes; only records.
   */
  recordServiceSignup(input: {
    human_id: string;
    agent_did: string;
    service_did: string;
  }): Promise<void>;
  /**
   * True when the owner has revoked minting for this (agent DID, service) pair
   * (§10.3.1). Consulted on the mint path before issuing; a missing row (a pair
   * never seen before) is NOT revoked.
   */
  isServiceSignupRevoked(agent_did: string, service_did: string): Promise<boolean>;
  /** The owner-facing connected-services list, newest signup first. */
  listServiceSignupsByHuman(human_id: string): Promise<ServiceSignupRecord[]>;
  /**
   * Owner toggles minting for one pair by row id, scoped to human_id so an
   * owner can only touch their own rows. `revoked=true` suspends, `false`
   * restores. Returns the updated row, or null on no match (unknown id or not
   * this human's) — mirrors revokeBinding's null-on-miss contract.
   */
  setServiceSignupRevoked(
    id: string,
    human_id: string,
    revoked: boolean,
  ): Promise<ServiceSignupRecord | null>;

  // Signing keys
  listActiveSigningKeys(): Promise<SigningKeyRecord[]>;
  insertSigningKey(input: InsertSigningKeyInput): Promise<SigningKeyRecord>;
  retireSigningKey(kid: string): Promise<void>;

  // Audit
  logIssuedToken(entry: TokenLogEntry): Promise<void>;
  recentTokensByHuman(
    human_id: string,
    limit: number,
  ): Promise<
    Array<{
      binding_id: string;
      agent_did: string;
      service_did: string;
      verification: VerificationMethod;
      issued_at: Date;
    }>
  >;
}
