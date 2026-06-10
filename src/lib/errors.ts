export type ErrorCode =
  | 'invalid_request'
  | 'invalid_signature'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'gone'
  | 'link_request_expired'
  | 'rate_limited'
  | 'invalid_attestation'
  | 'binding_revoked'
  | 'account_paused'
  | 'service_suspended'
  | 'binding_expired'
  | 'binding_not_ready'
  | 'agent_already_bound'
  | 'verification_required'
  | 'internal_error';

export interface ErrorEnvelope {
  error: {
    code: ErrorCode;
    message: string;
    details?: Record<string, unknown>;
  };
}

export class TrustError extends Error {
  readonly code: ErrorCode;
  readonly status: number;
  readonly details?: Record<string, unknown>;

  constructor(
    code: ErrorCode,
    message: string,
    status: number,
    details?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'TrustError';
    this.code = code;
    this.status = status;
    this.details = details;
  }

  toEnvelope(): ErrorEnvelope {
    return {
      error: {
        code: this.code,
        message: this.message,
        ...(this.details ? { details: this.details } : {}),
      },
    };
  }

  static invalidRequest(message: string, details?: Record<string, unknown>) {
    return new TrustError('invalid_request', message, 400, details);
  }
  static invalidSignature(message = 'Signature verification failed') {
    return new TrustError('invalid_signature', message, 401);
  }
  static unauthorized(message = 'Unauthorized') {
    return new TrustError('unauthorized', message, 401);
  }
  static forbidden(message = 'Forbidden') {
    return new TrustError('forbidden', message, 403);
  }
  static notFound(message = 'Not found') {
    return new TrustError('not_found', message, 404);
  }
  static conflict(message: string, details?: Record<string, unknown>) {
    return new TrustError('conflict', message, 409, details);
  }
  static gone(message: string) {
    return new TrustError('gone', message, 410);
  }
  /**
   * Poll-time 410 for the link ceremony: the link request expired before a
   * human confirmed, or the one-time binding token was already retrieved.
   * Distinct from the generic `gone` so agents can branch on "start over".
   */
  static linkRequestExpired(message: string) {
    return new TrustError('link_request_expired', message, 410);
  }
  static rateLimited(message = 'Rate limit exceeded') {
    return new TrustError('rate_limited', message, 429);
  }
  static bindingRevoked(message = 'Binding has been revoked') {
    return new TrustError('binding_revoked', message, 403);
  }
  /**
   * §8.4 owner kill-switch — the owner has paused the account, so the
   * attestor refuses to mint for ANY of its bindings. 403 (not 401):
   * authenticated-but-forbidden, the same family as `binding_revoked`,
   * so a consuming service treats it like a revocation rather than a
   * re-auth prompt. NOTE: this only stops NEW issuance; attestations
   * already minted stay valid until their `exp` (≤ §10.2 ceiling).
   *
   * Wire code `account_paused`. Operator-initiated take-down (a separate,
   * future action) is a distinct concept and would carry its own code.
   */
  static accountPaused(
    message = 'The owner has paused all agents on this account; they can resume it at trust.afauth.org/account',
  ) {
    return new TrustError('account_paused', message, 403);
  }
  /**
   * §10.3.1 per-service suspension — the owner has revoked minting for a
   * single (agent DID, service) pair at /account, while leaving the binding
   * and every other service intact. 403, the same authenticated-but-forbidden
   * family as `binding_revoked` / `account_paused`, so a consuming service
   * treats it as a revocation rather than a re-auth prompt. Stops only NEW
   * issuance for this pair; tokens already minted stay valid to their `exp`.
   * The agent MUST NOT retry for this `aud` until the owner restores it.
   */
  static serviceSuspended(
    message = 'The owner has revoked this service for this agent; they can restore it at trust.afauth.org/account',
  ) {
    return new TrustError('service_suspended', message, 403);
  }
  static bindingExpired(message = 'Binding token has expired; re-link the agent') {
    return new TrustError('binding_expired', message, 410);
  }
  static bindingNotReady(message = 'Link request not yet confirmed') {
    return new TrustError('binding_not_ready', message, 202);
  }
  /**
   * AFAP-0006 §10.5 — at most one active human binding per agent DID
   * per attestor. The message MUST NOT disclose which human currently
   * owns the binding (the existing owner's pseudonymity is preserved
   * even from would-be hijackers who guessed the agent DID).
   */
  static agentAlreadyBound(
    message = 'This agent identity is already linked to a different account. The current owner must revoke first.',
  ) {
    return new TrustError('agent_already_bound', message, 409);
  }
  static verificationRequired(
    message = 'Service requires a verification method this account does not have',
    details?: Record<string, unknown>,
  ) {
    return new TrustError('verification_required', message, 403, details);
  }
  static internal(message = 'Internal error') {
    return new TrustError('internal_error', message, 500);
  }
}
