import type { Context, MiddlewareHandler } from 'hono';
import { getCookie, setCookie, deleteCookie } from 'hono/cookie';
import { TrustError } from './errors.js';
import { generateToken, hashToken } from './tokens.js';
import type { HumanRecord, Store } from './store/index.js';

const SESSION_COOKIE = 'trust_sess';
export const SESSION_TTL_SECONDS = 30 * 24 * 60 * 60; // 30 days

export interface SessionContext {
  human: HumanRecord;
}

/**
 * Issues a fresh session for the given human and sets the cookie on
 * the response. Returns the raw bearer token in case the caller wants
 * to surface it (only used by tests).
 */
export async function createSessionCookie(
  c: Context,
  store: Store,
  human: HumanRecord,
): Promise<string> {
  const raw = generateToken();
  const hash = hashToken(raw);
  const expires = new Date(Date.now() + SESSION_TTL_SECONDS * 1000);
  await store.createSession(human.id, hash, expires);

  setCookie(c, SESSION_COOKIE, raw, {
    httpOnly: true,
    secure: !isDev(),
    sameSite: 'Lax',
    path: '/',
    maxAge: SESSION_TTL_SECONDS,
    expires,
  });
  return raw;
}

export async function clearSessionCookie(
  c: Context,
  store: Store,
): Promise<void> {
  const raw = getCookie(c, SESSION_COOKIE);
  if (raw) {
    const session = await store.getSessionByTokenHash(hashToken(raw));
    if (session) await store.deleteSession(session.id);
  }
  deleteCookie(c, SESSION_COOKIE, { path: '/' });
}

/**
 * Reads the session cookie and resolves the associated human, or
 * returns null if no valid session. Does not throw.
 */
export async function currentHuman(
  c: Context,
  store: Store,
): Promise<HumanRecord | null> {
  const raw = getCookie(c, SESSION_COOKIE);
  if (!raw) return null;
  const session = await store.getSessionByTokenHash(hashToken(raw));
  if (!session) return null;
  return store.getHumanById(session.human_id);
}

/**
 * Middleware that requires a signed-in human. On success, stashes
 * the human on the context (`c.set('human', …)`). On failure, throws
 * 401 — let route handlers redirect to /signin if they want a UX.
 */
export function requireHuman(store: Store): MiddlewareHandler {
  return async (c, next) => {
    const human = await currentHuman(c, store);
    if (!human) throw TrustError.unauthorized('Signed-in session required');
    c.set('human', human);
    await next();
  };
}

function isDev(): boolean {
  return process.env.NODE_ENV !== 'production';
}
