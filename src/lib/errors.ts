export type ErrorCode =
  | 'invalid_request'
  | 'invalid_signature'
  | 'unauthorized'
  | 'forbidden'
  | 'not_found'
  | 'conflict'
  | 'gone'
  | 'rate_limited'
  | 'invalid_attestation'
  | 'binding_revoked'
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
  static rateLimited(message = 'Rate limit exceeded') {
    return new TrustError('rate_limited', message, 429);
  }
  static bindingRevoked(message = 'Binding has been revoked') {
    return new TrustError('binding_revoked', message, 403);
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
