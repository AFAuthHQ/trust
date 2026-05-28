import RedisMock from 'ioredis-mock';
import type Redis from 'ioredis';
import { Hono } from 'hono';
import { generateKeyPair, exportJWK } from 'jose';
import {
  type KeyObject,
  createPrivateKey,
  sign as cryptoSign,
} from 'node:crypto';
import { createApp } from '../src/server.js';
import { MemoryStore } from '../src/lib/store/memory.js';
import { PgEncryptedKeyVault, type KeyVault } from '../src/lib/keyvault.js';
import type { GoogleOauthDeps } from '../src/lib/oauth/google.js';
import type { Store } from '../src/lib/store/index.js';

/**
 * Sets all required env vars so getConfig() succeeds in tests.
 * Call once at the top of each test file.
 */
export function setTestEnv(): void {
  process.env.NODE_ENV = 'test';
  process.env.PORT = '3001';
  process.env.LOG_LEVEL = 'error';
  process.env.DATABASE_URL = 'postgres://test:test@localhost:5432/test';
  process.env.REDIS_URL = 'redis://localhost:6379';
  process.env.TRUST_SESSION_SECRET = 'test-session-secret-must-be-at-least-32-bytes-long-xx';
  process.env.TRUST_ADMIN_SECRET = 'test-admin-secret-16';
  process.env.TRUST_KEK_BASE64 = Buffer.alloc(32, 0xab).toString('base64');
  process.env.TRUST_PSEUDONYM_KEY_BASE64 = Buffer.alloc(32, 0xcd).toString('base64');
  process.env.PUBLIC_BASE_URL = 'http://localhost:3001';
  process.env.JWKS_PUBLIC_URL = 'http://localhost:3001/.well-known/jwks.json';
  process.env.EMAIL_PROVIDER = 'stdout';
  process.env.EMAIL_FROM = 'no-reply@trust.afauth.org';
}

// Set immediately at module load — `getConfig()` memoizes on first read,
// which can happen during top-level imports of route modules.
setTestEnv();

export interface TestHarness {
  app: Hono;
  store: Store;
  redis: Redis;
  vault: KeyVault;
}

export async function createTestHarness(
  opts: { googleOauthDeps?: GoogleOauthDeps } = {},
): Promise<TestHarness> {
  setTestEnv();
  const store = new MemoryStore();
  const redis = new (RedisMock as unknown as new () => Redis)();
  const kek = Buffer.from(process.env.TRUST_KEK_BASE64!, 'base64');
  const vault = new PgEncryptedKeyVault(store, kek);
  await vault.ensureActiveKey();
  const app = createApp({
    store,
    redis,
    vault,
    googleOauthDeps: opts.googleOauthDeps,
  });
  return { app, store, redis, vault };
}

/** Ed25519 keypair + matching did:key for a synthetic agent. */
export async function createAgentKeypair(): Promise<{
  publicKeyB64: string;
  privateKey: KeyObject;
  did: string;
}> {
  const { publicKey, privateKey } = await generateKeyPair('EdDSA', {
    extractable: true,
  });
  const pubJwk = await exportJWK(publicKey);
  const privJwk = await exportJWK(privateKey);
  if (!pubJwk.x) throw new Error('exported JWK missing x');
  const nodePriv = createPrivateKey({
    key: privJwk as unknown as Record<string, unknown>,
    format: 'jwk',
  });
  const pubBytes = base64UrlDecode(pubJwk.x);
  const did = encodeDidKey(pubBytes);
  return { publicKeyB64: pubJwk.x, privateKey: nodePriv, did };
}

function base64UrlDecode(s: string): Uint8Array {
  const padded = s + '='.repeat((4 - (s.length % 4)) % 4);
  return new Uint8Array(
    Buffer.from(padded.replace(/-/g, '+').replace(/_/g, '/'), 'base64'),
  );
}

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function encodeDidKey(pub: Uint8Array): string {
  const buf = new Uint8Array(2 + pub.length);
  buf[0] = 0xed;
  buf[1] = 0x01;
  buf.set(pub, 2);
  return `did:key:z${base58btcEncode(buf)}`;
}

function base58btcEncode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  const digits: number[] = [];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i]!;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = '';
  for (let i = 0; i < zeros; i++) out += BASE58_ALPHABET[0];
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58_ALPHABET[digits[i]!];
  return out;
}

export async function signEd25519(
  privateKey: KeyObject,
  message: Uint8Array,
): Promise<string> {
  const sig = cryptoSign(null, message, privateKey);
  return base64UrlEncode(new Uint8Array(sig));
}

function base64UrlEncode(buf: Uint8Array): string {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/=+$/, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

/** Convenience: post JSON to the test app. */
export async function postJson(
  app: Hono,
  path: string,
  body: unknown,
  init: { headers?: Record<string, string> } = {},
): Promise<Response> {
  return app.request(path, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(init.headers ?? {}),
    },
    body: JSON.stringify(body),
  });
}
