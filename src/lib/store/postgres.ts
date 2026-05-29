import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import type { JWK } from 'jose';
import { getConfig } from '../config.js';
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

const PG_UNIQUE_VIOLATION = '23505';
const BINDINGS_ACTIVE_AGENT_DID_IDX = 'bindings_active_agent_did_idx';

function isAgentDidUniqueViolation(err: unknown): boolean {
  if (!err || typeof err !== 'object') return false;
  const e = err as { code?: string; constraint?: string };
  return e.code === PG_UNIQUE_VIOLATION && e.constraint === BINDINGS_ACTIVE_AGENT_DID_IDX;
}
import type { VerificationMethod } from '../schemas.js';

export class PgStore implements Store {
  readonly pool: Pool;

  constructor(connectionString?: string) {
    this.pool = new Pool({
      connectionString: connectionString ?? getConfig().DATABASE_URL,
      max: 10,
      idleTimeoutMillis: 30_000,
    });
  }

  async init(): Promise<void> {
    // Apply every migration file in lexical order. Each .sql file is
    // its own transaction inside the per-file pool.query call; the
    // files themselves are written to be idempotent (IF NOT EXISTS /
    // IF EXISTS) where applicable, so re-running them on an already-
    // migrated database is safe.
    const dir = join(process.cwd(), 'migrations');
    const files = (await readdir(dir)).filter((f) => f.endsWith('.sql')).sort();
    const client = await this.pool.connect();
    try {
      for (const file of files) {
        const sql = await readFile(join(dir, file), 'utf8');
        await client.query(sql);
      }
    } finally {
      client.release();
    }
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  // -------------------------------------------------------------------
  // Humans
  // -------------------------------------------------------------------

  async getHumanByEmail(email: string): Promise<HumanRecord | null> {
    const { rows } = await this.pool.query(
      'SELECT * FROM humans WHERE primary_email = $1',
      [canonicalizeEmail(email)],
    );
    return rows[0] ? toHuman(rows[0]) : null;
  }

  async getHumanById(id: string): Promise<HumanRecord | null> {
    const { rows } = await this.pool.query('SELECT * FROM humans WHERE id = $1', [id]);
    return rows[0] ? toHuman(rows[0]) : null;
  }

  async upsertHuman(input: CreateHumanInput): Promise<HumanRecord> {
    const email = canonicalizeEmail(input.primary_email);
    const { rows } = await this.pool.query(
      `INSERT INTO humans (primary_email) VALUES ($1)
       ON CONFLICT (primary_email) DO UPDATE SET primary_email = EXCLUDED.primary_email
       RETURNING *`,
      [email],
    );
    return toHuman(rows[0]);
  }

  // -------------------------------------------------------------------
  // Verifications
  // -------------------------------------------------------------------

  async recordVerification(
    human_id: string,
    method: VerificationMethod,
    provider: string,
    external_subject?: string,
  ): Promise<VerificationRecord> {
    const { rows } = await this.pool.query(
      `INSERT INTO verifications (human_id, method, provider, external_subject)
         VALUES ($1, $2, $3, $4)
       ON CONFLICT (human_id, method, provider) DO UPDATE
         SET verified_at = now(),
             revoked_at = NULL,
             external_subject = COALESCE(EXCLUDED.external_subject, verifications.external_subject)
       RETURNING *`,
      [human_id, method, provider, external_subject ?? null],
    );
    return toVerification(rows[0]);
  }

  async listVerifications(human_id: string): Promise<VerificationRecord[]> {
    const { rows } = await this.pool.query(
      'SELECT * FROM verifications WHERE human_id = $1 AND revoked_at IS NULL ORDER BY verified_at DESC',
      [human_id],
    );
    return rows.map(toVerification);
  }

  async findVerificationByExternalSubject(
    provider: string,
    external_subject: string,
  ): Promise<VerificationRecord | null> {
    const { rows } = await this.pool.query(
      `SELECT * FROM verifications
       WHERE provider = $1 AND external_subject = $2 AND revoked_at IS NULL`,
      [provider, external_subject],
    );
    return rows[0] ? toVerification(rows[0]) : null;
  }

  async revokeVerification(
    human_id: string,
    method: VerificationMethod,
    provider: string,
  ): Promise<void> {
    await this.pool.query(
      `UPDATE verifications SET revoked_at = now()
       WHERE human_id = $1 AND method = $2 AND provider = $3 AND revoked_at IS NULL`,
      [human_id, method, provider],
    );
  }

  // -------------------------------------------------------------------
  // Sessions
  // -------------------------------------------------------------------

  async createSession(
    human_id: string,
    token_hash: string,
    expires_at: Date,
  ): Promise<SessionRecord> {
    const { rows } = await this.pool.query(
      `INSERT INTO sessions (human_id, token_hash, expires_at) VALUES ($1, $2, $3) RETURNING *`,
      [human_id, token_hash, expires_at],
    );
    return toSession(rows[0]);
  }

  async getSessionByTokenHash(token_hash: string): Promise<SessionRecord | null> {
    const { rows } = await this.pool.query(
      'SELECT * FROM sessions WHERE token_hash = $1 AND expires_at > now()',
      [token_hash],
    );
    if (!rows[0]) return null;
    await this.pool.query('UPDATE sessions SET last_seen_at = now() WHERE id = $1', [rows[0].id]);
    return toSession(rows[0]);
  }

  async deleteSession(id: string): Promise<void> {
    await this.pool.query('DELETE FROM sessions WHERE id = $1', [id]);
  }

  // -------------------------------------------------------------------
  // Magic links
  // -------------------------------------------------------------------

  async createMagicLink(
    email: string,
    token_hash: string,
    expires_at: Date,
    next_path?: string,
  ): Promise<MagicLinkRecord> {
    const { rows } = await this.pool.query(
      `INSERT INTO magic_links (email, token_hash, expires_at, next_path)
       VALUES ($1, $2, $3, $4) RETURNING *`,
      [canonicalizeEmail(email), token_hash, expires_at, next_path ?? null],
    );
    return toMagicLink(rows[0]);
  }

  async peekMagicLink(token_hash: string): Promise<MagicLinkRecord | null> {
    const { rows } = await this.pool.query(
      `SELECT * FROM magic_links
       WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()`,
      [token_hash],
    );
    return rows[0] ? toMagicLink(rows[0]) : null;
  }

  async consumeMagicLink(token_hash: string): Promise<MagicLinkRecord | null> {
    const { rows } = await this.pool.query(
      `UPDATE magic_links SET consumed_at = now()
       WHERE token_hash = $1 AND consumed_at IS NULL AND expires_at > now()
       RETURNING *`,
      [token_hash],
    );
    return rows[0] ? toMagicLink(rows[0]) : null;
  }

  // -------------------------------------------------------------------
  // Link requests
  // -------------------------------------------------------------------

  async createLinkRequest(input: CreateLinkRequestInput): Promise<LinkRequestRecord> {
    const { rows } = await this.pool.query(
      `INSERT INTO link_requests
         (agent_did, agent_label, agent_pubkey_b64, state, expires_at, callback_url)
       VALUES ($1, $2, $3, 'pending', $4, $5)
       RETURNING *`,
      [
        input.agent_did,
        input.agent_label ?? null,
        input.agent_pubkey_b64,
        input.expires_at,
        input.callback_url ?? null,
      ],
    );
    return toLinkRequest(rows[0]);
  }

  async getLinkRequest(id: string): Promise<LinkRequestRecord | null> {
    const { rows } = await this.pool.query('SELECT * FROM link_requests WHERE id = $1', [id]);
    return rows[0] ? toLinkRequest(rows[0]) : null;
  }

  async confirmLinkRequest(
    id: string,
    human_id: string,
    binding_id: string,
  ): Promise<LinkRequestRecord | null> {
    const { rows } = await this.pool.query(
      `UPDATE link_requests
         SET state = 'confirmed', human_id = $2, binding_id = $3, confirmed_at = now()
       WHERE id = $1 AND state = 'pending' AND expires_at > now()
       RETURNING *`,
      [id, human_id, binding_id],
    );
    return rows[0] ? toLinkRequest(rows[0]) : null;
  }

  // -------------------------------------------------------------------
  // Bindings
  // -------------------------------------------------------------------

  async createBinding(input: CreateBindingInput): Promise<BindingRecord> {
    // §10.5 — at most one active binding per agent_did per attestor.
    // Lock any existing active row inside a transaction so concurrent
    // /v1/link/confirm calls can't both reach INSERT.
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');

      const existing = await client.query(
        'SELECT * FROM bindings WHERE agent_did = $1 AND revoked_at IS NULL FOR UPDATE',
        [input.agent_did],
      );

      if (existing.rows.length > 0) {
        const row = existing.rows[0];
        if (row.human_id !== input.human_id) {
          await client.query('ROLLBACK');
          throw TrustError.agentAlreadyBound();
        }
        // Same human re-linking — refresh the active binding in place
        // (rotates the binding_token and pubkey).
        const updated = await client.query(
          `UPDATE bindings SET
             agent_label = $1,
             agent_pubkey_b64 = $2,
             binding_token_hash = $3,
             expires_at = $4
           WHERE id = $5 RETURNING *`,
          [
            input.agent_label ?? null,
            input.agent_pubkey_b64,
            input.binding_token_hash,
            input.expires_at,
            row.id,
          ],
        );
        await client.query('COMMIT');
        return toBinding(updated.rows[0]);
      }

      const inserted = await client.query(
        `INSERT INTO bindings
           (human_id, agent_did, agent_label, agent_pubkey_b64, binding_token_hash, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING *`,
        [
          input.human_id,
          input.agent_did,
          input.agent_label ?? null,
          input.agent_pubkey_b64,
          input.binding_token_hash,
          input.expires_at,
        ],
      );
      await client.query('COMMIT');
      return toBinding(inserted.rows[0]);
    } catch (err) {
      await client.query('ROLLBACK').catch(() => {});
      // Defense-in-depth: if the partial unique index still fires
      // (e.g., a concurrent commit slipped past the SELECT FOR UPDATE
      // window via a different connection that skipped the lock),
      // translate to the public-facing error.
      if (isAgentDidUniqueViolation(err)) {
        throw TrustError.agentAlreadyBound();
      }
      throw err;
    } finally {
      client.release();
    }
  }

  async getBindingByTokenHash(token_hash: string): Promise<BindingRecord | null> {
    const { rows } = await this.pool.query(
      'SELECT * FROM bindings WHERE binding_token_hash = $1',
      [token_hash],
    );
    return rows[0] ? toBinding(rows[0]) : null;
  }

  async getBindingById(id: string): Promise<BindingRecord | null> {
    const { rows } = await this.pool.query('SELECT * FROM bindings WHERE id = $1', [id]);
    return rows[0] ? toBinding(rows[0]) : null;
  }

  async findActiveBindingByAgentDid(agent_did: string): Promise<BindingRecord | null> {
    const { rows } = await this.pool.query(
      'SELECT * FROM bindings WHERE agent_did = $1 AND revoked_at IS NULL LIMIT 1',
      [agent_did],
    );
    return rows[0] ? toBinding(rows[0]) : null;
  }

  async listBindingsByHuman(human_id: string): Promise<BindingRecord[]> {
    const { rows } = await this.pool.query(
      'SELECT * FROM bindings WHERE human_id = $1 ORDER BY created_at DESC',
      [human_id],
    );
    return rows.map(toBinding);
  }

  async revokeBinding(id: string, human_id: string): Promise<BindingRecord | null> {
    const { rows } = await this.pool.query(
      `UPDATE bindings SET revoked_at = now()
       WHERE id = $1 AND human_id = $2 AND revoked_at IS NULL
       RETURNING *`,
      [id, human_id],
    );
    return rows[0] ? toBinding(rows[0]) : null;
  }

  async touchBindingLastUsed(id: string, when: Date): Promise<void> {
    await this.pool.query('UPDATE bindings SET last_used_at = $2 WHERE id = $1', [id, when]);
  }

  // -------------------------------------------------------------------
  // Signing keys
  // -------------------------------------------------------------------

  async listActiveSigningKeys(): Promise<SigningKeyRecord[]> {
    const { rows } = await this.pool.query(
      'SELECT * FROM signing_keys WHERE retired_at IS NULL ORDER BY active_from DESC',
    );
    return rows.map(toSigningKey);
  }

  async retireSigningKey(kid: string): Promise<void> {
    await this.pool.query(
      `UPDATE signing_keys SET retired_at = now() WHERE kid = $1 AND retired_at IS NULL`,
      [kid],
    );
  }

  async insertSigningKey(input: InsertSigningKeyInput): Promise<SigningKeyRecord> {
    const { rows } = await this.pool.query(
      `INSERT INTO signing_keys
         (kid, alg, public_jwk, private_jwk_enc, private_jwk_iv, active_from)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [
        input.kid,
        input.alg,
        input.publicJwk,
        input.privateJwkEnc,
        input.privateJwkIv,
        input.activeFrom,
      ],
    );
    return toSigningKey(rows[0]);
  }

  // -------------------------------------------------------------------
  // Audit
  // -------------------------------------------------------------------

  async logIssuedToken(entry: TokenLogEntry): Promise<void> {
    await this.pool.query(
      `INSERT INTO token_log (binding_id, service_did, verification, kid, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [entry.binding_id, entry.service_did, entry.verification, entry.kid, entry.expires_at],
    );
  }

  async recentTokensByHuman(
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
  > {
    const { rows } = await this.pool.query(
      `SELECT t.binding_id, b.agent_did, t.service_did, t.verification, t.issued_at
         FROM token_log t
         JOIN bindings b ON b.id = t.binding_id
        WHERE b.human_id = $1
        ORDER BY t.issued_at DESC
        LIMIT $2`,
      [human_id, limit],
    );
    return rows as Array<{
      binding_id: string;
      agent_did: string;
      service_did: string;
      verification: VerificationMethod;
      issued_at: Date;
    }>;
  }
}

// ---------------------------------------------------------------------
// Row → record mappers
// ---------------------------------------------------------------------

function toHuman(r: any): HumanRecord {
  return {
    id: r.id,
    primary_email: r.primary_email,
    created_at: r.created_at,
    disabled_at: r.disabled_at,
  };
}

function toVerification(r: any): VerificationRecord {
  return {
    id: r.id,
    human_id: r.human_id,
    method: r.method,
    provider: r.provider,
    external_subject: r.external_subject ?? null,
    verified_at: r.verified_at,
    revoked_at: r.revoked_at,
  };
}

function toSession(r: any): SessionRecord {
  return {
    id: r.id,
    human_id: r.human_id,
    token_hash: r.token_hash,
    created_at: r.created_at,
    expires_at: r.expires_at,
  };
}

function toMagicLink(r: any): MagicLinkRecord {
  return {
    id: r.id,
    email: r.email,
    token_hash: r.token_hash,
    expires_at: r.expires_at,
    consumed_at: r.consumed_at,
    next_path: r.next_path,
  };
}

function toLinkRequest(r: any): LinkRequestRecord {
  return {
    id: r.id,
    agent_did: r.agent_did,
    agent_label: r.agent_label,
    agent_pubkey_b64: r.agent_pubkey_b64,
    state: r.state,
    human_id: r.human_id,
    binding_id: r.binding_id,
    created_at: r.created_at,
    expires_at: r.expires_at,
    confirmed_at: r.confirmed_at,
    callback_url: r.callback_url,
  };
}

function toBinding(r: any): BindingRecord {
  return {
    id: r.id,
    human_id: r.human_id,
    agent_did: r.agent_did,
    agent_label: r.agent_label,
    agent_pubkey_b64: r.agent_pubkey_b64,
    binding_token_hash: r.binding_token_hash,
    created_at: r.created_at,
    expires_at: r.expires_at,
    revoked_at: r.revoked_at,
    last_used_at: r.last_used_at,
  };
}

function toSigningKey(r: any): SigningKeyRecord {
  return {
    kid: r.kid,
    alg: r.alg,
    publicJwk: r.public_jwk as JWK,
    privateJwkEnc: r.private_jwk_enc,
    privateJwkIv: r.private_jwk_iv,
    createdAt: r.created_at,
    activeFrom: r.active_from,
    retiredAt: r.retired_at,
  };
}
