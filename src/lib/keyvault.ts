/**
 * KeyVault — the abstraction over "where the private signing key
 * material lives." All §10 attestation JWT signing flows through
 * this interface so that swapping Postgres-encrypted storage for a
 * real KMS provider is a single-file change.
 *
 * v0.1 ships one production-ready implementation:
 *
 *   PgEncryptedKeyVault — stores private JWKs in Postgres as
 *   AES-256-GCM ciphertext, decryptable only with the KEK supplied
 *   via the TRUST_KEK_BASE64 env var. The KEK never lives in the
 *   database; rotating it is a separate, documented operation
 *   (decrypt-all with old KEK, re-encrypt with new KEK).
 *
 * Stubs are provided for AwsKmsKeyVault and GcpKmsKeyVault so the
 * shape of those integrations is documented in code rather than in a
 * README. Wiring them is straightforward — see the constructor
 * comments — but the actual SDK dependencies are deferred to keep
 * this package KMS-provider-agnostic.
 */

import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
} from 'node:crypto';
import {
  exportJWK,
  generateKeyPair,
  importJWK,
  type JWK,
  type KeyLike,
} from 'jose';
import { TrustError } from './errors.js';
import type { Store } from './store/index.js';

export const ATTESTATION_JWT_ALG = 'EdDSA' as const;

export interface KeyMetadata {
  kid: string;
  alg: string;
  publicJwk: JWK;
  createdAt: Date;
  activeFrom: Date;
  retiredAt: Date | null;
}

export interface KeyVault {
  /** Lists known keys, sorted most-recently-active first. */
  list(): Promise<KeyMetadata[]>;

  /**
   * Generates a fresh EdDSA keypair, persists it (encrypted at rest),
   * and returns its metadata. Always sets activeFrom=now unless
   * overridden.
   */
  rotate(opts?: { activeFrom?: Date; kidPrefix?: string }): Promise<KeyMetadata>;

  /**
   * If no active key exists, rotates to create one. Idempotent —
   * called on every boot to guarantee a key is available.
   */
  ensureActiveKey(): Promise<KeyMetadata>;

  /**
   * Returns the *active* key (most recent, not retired). Throws
   * TrustError if none.
   */
  getActive(): Promise<KeyMetadata>;

  /**
   * Returns a jose KeyLike for signing with `kid`. The private
   * material is materialised in memory only for the duration of the
   * call's awaiter — implementations MUST NOT cache decrypted
   * material in long-lived storage.
   */
  getSigningKey(kid: string): Promise<KeyLike>;

  /**
   * Marks a key as retired. Retired keys are excluded from
   * `/.well-known/jwks.json` and from `getActive()`, but the row
   * stays in the store for forensics. Idempotent.
   */
  retire(kid: string): Promise<void>;
}

// ---------------------------------------------------------------------
// PgEncryptedKeyVault
// ---------------------------------------------------------------------

const GCM_IV_BYTES = 12; // 96-bit IVs are the NIST-recommended GCM size

/**
 * Postgres-backed KeyVault with AES-256-GCM encryption at rest.
 *
 * The Store is treated as opaque bytes storage — it never sees
 * cleartext private material after this constructor runs. The KEK
 * lives in process memory (loaded from env), and decrypted JWKs
 * exist only as transient awaitables passed into `jose.SignJWT`.
 */
export class PgEncryptedKeyVault implements KeyVault {
  constructor(
    private readonly store: Store,
    /** 32 bytes. Use 256-bit key for AES-256-GCM. */
    private readonly kek: Uint8Array,
  ) {
    if (kek.length !== 32) {
      throw new Error(
        `PgEncryptedKeyVault: KEK MUST be 32 bytes (256 bits); got ${kek.length}`,
      );
    }
  }

  async list(): Promise<KeyMetadata[]> {
    const rows = await this.store.listActiveSigningKeys();
    return rows.map((r) => ({
      kid: r.kid,
      alg: r.alg,
      publicJwk: r.publicJwk,
      createdAt: r.createdAt,
      activeFrom: r.activeFrom,
      retiredAt: r.retiredAt,
    }));
  }

  async rotate(opts: { activeFrom?: Date; kidPrefix?: string } = {}): Promise<KeyMetadata> {
    const kid = `${opts.kidPrefix ?? 'tk'}-${new Date().toISOString().slice(0, 10)}-${randomBytes(3).toString('hex')}`;
    const { publicKey, privateKey } = await generateKeyPair(ATTESTATION_JWT_ALG, {
      extractable: true,
    });
    const publicJwk = await exportJWK(publicKey);
    const privateJwk = await exportJWK(privateKey);
    publicJwk.kid = kid;
    publicJwk.alg = ATTESTATION_JWT_ALG;
    publicJwk.use = 'sig';
    privateJwk.kid = kid;
    privateJwk.alg = ATTESTATION_JWT_ALG;

    const { ciphertext, iv } = this.encryptJwk(privateJwk);

    const activeFrom = opts.activeFrom ?? new Date();
    const inserted = await this.store.insertSigningKey({
      kid,
      alg: ATTESTATION_JWT_ALG,
      publicJwk,
      privateJwkEnc: ciphertext,
      privateJwkIv: iv,
      activeFrom,
    });
    return {
      kid,
      alg: ATTESTATION_JWT_ALG,
      publicJwk,
      createdAt: inserted.createdAt,
      activeFrom,
      retiredAt: null,
    };
  }

  async ensureActiveKey(): Promise<KeyMetadata> {
    const existing = await this.getActiveOrNull();
    if (existing) return existing;
    return this.rotate();
  }

  async getActive(): Promise<KeyMetadata> {
    const k = await this.getActiveOrNull();
    if (!k) throw TrustError.internal('No active signing key configured');
    return k;
  }

  async getSigningKey(kid: string): Promise<KeyLike> {
    const rows = await this.store.listActiveSigningKeys();
    const row = rows.find((r) => r.kid === kid);
    if (!row) throw TrustError.internal(`signing key not found: ${kid}`);
    const jwk = this.decryptJwk(row.privateJwkEnc, row.privateJwkIv);
    const key = await importJWK(jwk, ATTESTATION_JWT_ALG);
    if (!isKeyLike(key)) {
      throw TrustError.internal('importJWK returned Uint8Array — expected asymmetric key');
    }
    return key;
  }

  async retire(kid: string): Promise<void> {
    await this.store.retireSigningKey(kid);
  }

  private async getActiveOrNull(): Promise<KeyMetadata | null> {
    const all = await this.list();
    const now = Date.now();
    const eligible = all
      .filter((k) => k.retiredAt === null && k.activeFrom.getTime() <= now)
      .sort((a, b) => {
        // Primary: most recently activated first.
        const dt = b.activeFrom.getTime() - a.activeFrom.getTime();
        if (dt !== 0) return dt;
        // Tiebreak: most recently inserted. Sort stability is not
        // enough here — when two rotations land in the same
        // millisecond (operator double-click, fast tests), the
        // newer one should win for deterministic "most recent"
        // semantics.
        return b.createdAt.getTime() - a.createdAt.getTime();
      });
    return eligible[0] ?? null;
  }

  private encryptJwk(jwk: JWK): { ciphertext: Buffer; iv: Buffer } {
    const iv = randomBytes(GCM_IV_BYTES);
    const cipher = createCipheriv('aes-256-gcm', this.kek, iv);
    const plain = Buffer.from(JSON.stringify(jwk), 'utf8');
    const enc = Buffer.concat([cipher.update(plain), cipher.final()]);
    const tag = cipher.getAuthTag(); // 16 bytes
    // Stored layout: ciphertext || tag  (IV stored alongside).
    return { ciphertext: Buffer.concat([enc, tag]), iv };
  }

  private decryptJwk(ciphertextWithTag: Buffer, iv: Buffer): JWK {
    if (iv.length !== GCM_IV_BYTES) {
      throw TrustError.internal(`signing-key IV is ${iv.length} bytes; expected ${GCM_IV_BYTES}`);
    }
    if (ciphertextWithTag.length < 16) {
      throw TrustError.internal('signing-key ciphertext too short to contain GCM tag');
    }
    const tag = ciphertextWithTag.subarray(ciphertextWithTag.length - 16);
    const ct = ciphertextWithTag.subarray(0, ciphertextWithTag.length - 16);
    const decipher = createDecipheriv('aes-256-gcm', this.kek, iv);
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(ct), decipher.final()]);
    return JSON.parse(plain.toString('utf8')) as JWK;
  }
}

// ---------------------------------------------------------------------
// KMS provider stubs
// ---------------------------------------------------------------------

/**
 * AwsKmsKeyVault — sketch only. Wiring requires adding
 * @aws-sdk/client-kms to deps and adapting list/rotate to KMS's
 * key-policy model (KMS does not generate keys with arbitrary kids;
 * use a kid → KMS keyArn map). Signing flows through `KMSClient.send(
 * new SignCommand(...))` with MessageType='RAW' and
 * SigningAlgorithm='ECDSA_SHA_256' (KMS does not support Ed25519 as
 * of 2026; for EdDSA prefer GcpKmsKeyVault or a custom-EdDSA option
 * like HSM-backed Vault).
 */
export class AwsKmsKeyVault implements KeyVault {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(_opts: { region: string; kmsArnPrefix: string; store: Store }) {
    throw new Error('AwsKmsKeyVault: not yet implemented — see lib/keyvault.ts');
  }
  async list(): Promise<KeyMetadata[]> { throw new Error('not implemented'); }
  async rotate(): Promise<KeyMetadata> { throw new Error('not implemented'); }
  async ensureActiveKey(): Promise<KeyMetadata> { throw new Error('not implemented'); }
  async getActive(): Promise<KeyMetadata> { throw new Error('not implemented'); }
  async getSigningKey(): Promise<KeyLike> { throw new Error('not implemented'); }
  async retire(): Promise<void> { throw new Error('not implemented'); }
}

/**
 * GcpKmsKeyVault — sketch only. Wiring requires
 * @google-cloud/kms; GCP KMS does support EdDSA (key purpose
 * ASYMMETRIC_SIGN, algorithm EC_SIGN_ED25519). list() enumerates
 * CryptoKeyVersions, rotate() creates a new version with state
 * ENABLED, getSigningKey() returns a KeyLike that wraps a
 * KeyManagementServiceClient.asymmetricSign call.
 */
export class GcpKmsKeyVault implements KeyVault {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  constructor(_opts: { keyRing: string; keyName: string; store: Store }) {
    throw new Error('GcpKmsKeyVault: not yet implemented — see lib/keyvault.ts');
  }
  async list(): Promise<KeyMetadata[]> { throw new Error('not implemented'); }
  async rotate(): Promise<KeyMetadata> { throw new Error('not implemented'); }
  async ensureActiveKey(): Promise<KeyMetadata> { throw new Error('not implemented'); }
  async getActive(): Promise<KeyMetadata> { throw new Error('not implemented'); }
  async getSigningKey(): Promise<KeyLike> { throw new Error('not implemented'); }
  async retire(): Promise<void> { throw new Error('not implemented'); }
}

// ---------------------------------------------------------------------

function isKeyLike(k: KeyLike | Uint8Array): k is KeyLike {
  return !(k instanceof Uint8Array);
}
