import { readFile, readdir } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import type { JWK } from 'jose';
import { getConfig } from '../config.js';
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
      [email.toLowerCase()],
    );
    return rows[0] ? toHuman(rows[0]) : null;
  }

  async getHumanById(id: string): Promise<HumanRecord | null> {
    const { rows } = await this.pool.query('SELECT * FROM humans WHERE id = $1', [id]);
    return rows[0] ? toHuman(rows[0]) : null;
  }

  async upsertHuman(input: CreateHumanInput): Promise<HumanRecord> {
    const email = input.primary_email.toLowerCase();
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
  ): Promise<VerificationRecord> {
    const { rows } = await this.pool.query(
      `INSERT INTO verifications (human_id, method, provider) VALUES ($1, $2, $3)
       ON CONFLICT (human_id, method, provider) DO UPDATE
         SET verified_at = now(), revoked_at = NULL
       RETURNING *`,
      [human_id, method, provider],
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
      [email.toLowerCase(), token_hash, expires_at, next_path ?? null],
    );
    return toMagicLink(rows[0]);
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
    const { rows } = await this.pool.query(
      `INSERT INTO bindings
         (human_id, agent_did, agent_label, agent_pubkey_b64, binding_token_hash, expires_at)
       VALUES ($1, $2, $3, $4, $5, $6)
       ON CONFLICT (human_id, agent_did) DO UPDATE SET
         agent_label = EXCLUDED.agent_label,
         agent_pubkey_b64 = EXCLUDED.agent_pubkey_b64,
         binding_token_hash = EXCLUDED.binding_token_hash,
         expires_at = EXCLUDED.expires_at,
         revoked_at = NULL
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
    return toBinding(rows[0]);
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
