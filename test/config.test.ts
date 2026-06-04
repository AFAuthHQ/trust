import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { setTestEnv } from './helpers.js';
import { getConfig, resetConfigForTest } from '../src/lib/config.js';

describe('EMAIL_FROM validator', () => {
  beforeEach(() => {
    setTestEnv();
    resetConfigForTest();
  });
  afterEach(() => {
    resetConfigForTest();
  });

  it('accepts a bare email', () => {
    process.env.EMAIL_FROM = 'support@afauth.org';
    resetConfigForTest();
    expect(getConfig().EMAIL_FROM).toBe('support@afauth.org');
  });

  it('accepts a `Display Name <email>` name-addr', () => {
    process.env.EMAIL_FROM = 'AFAuth <support@afauth.org>';
    resetConfigForTest();
    expect(getConfig().EMAIL_FROM).toBe('AFAuth <support@afauth.org>');
  });

  it('accepts a name-addr with quoted-style spacing', () => {
    process.env.EMAIL_FROM = 'AFAuth Trust Attestor <no-reply@trust.afauth.org>';
    resetConfigForTest();
    expect(getConfig().EMAIL_FROM).toBe(
      'AFAuth Trust Attestor <no-reply@trust.afauth.org>',
    );
  });

  it('rejects a missing @', () => {
    process.env.EMAIL_FROM = 'AFAuth <not-an-email>';
    resetConfigForTest();
    expect(() => getConfig()).toThrow(/EMAIL_FROM/);
  });

  it('rejects bare gibberish', () => {
    process.env.EMAIL_FROM = 'just some text';
    resetConfigForTest();
    expect(() => getConfig()).toThrow(/EMAIL_FROM/);
  });

  it('rejects an empty string', () => {
    process.env.EMAIL_FROM = '';
    resetConfigForTest();
    expect(() => getConfig()).toThrow(/EMAIL_FROM/);
  });
});

describe('TRUST_E2E_AUTOCONFIRM production guard', () => {
  beforeEach(() => {
    setTestEnv();
    resetConfigForTest();
  });
  afterEach(() => {
    delete process.env.TRUST_E2E_AUTOCONFIRM;
    resetConfigForTest();
  });

  it('refuses to boot when NODE_ENV=production and TRUST_E2E_AUTOCONFIRM=1', () => {
    process.env.NODE_ENV = 'production';
    process.env.TRUST_E2E_AUTOCONFIRM = '1';
    resetConfigForTest();
    expect(() => getConfig()).toThrow(/TRUST_E2E_AUTOCONFIRM/);
  });

  it('refuses to boot when NODE_ENV=production and TRUST_E2E_AUTOCONFIRM=true', () => {
    process.env.NODE_ENV = 'production';
    process.env.TRUST_E2E_AUTOCONFIRM = 'true';
    resetConfigForTest();
    expect(() => getConfig()).toThrow(/TRUST_E2E_AUTOCONFIRM/);
  });

  it('allows TRUST_E2E_AUTOCONFIRM=1 in non-production envs', () => {
    process.env.NODE_ENV = 'test';
    process.env.TRUST_E2E_AUTOCONFIRM = '1';
    resetConfigForTest();
    expect(getConfig().TRUST_E2E_AUTOCONFIRM).toBe(true);

    process.env.NODE_ENV = 'development';
    resetConfigForTest();
    expect(getConfig().TRUST_E2E_AUTOCONFIRM).toBe(true);
  });

  it('allows NODE_ENV=production when the flag is unset or 0', () => {
    // Production boot also requires strong secrets and a real email
    // provider (see guards below); set them so this test isolates the
    // E2E-flag behaviour.
    process.env.TRUST_SESSION_SECRET = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4';
    process.env.TRUST_ADMIN_SECRET = 'f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3';
    process.env.EMAIL_PROVIDER = 'resend';
    process.env.NODE_ENV = 'production';
    delete process.env.TRUST_E2E_AUTOCONFIRM;
    resetConfigForTest();
    expect(getConfig().TRUST_E2E_AUTOCONFIRM).toBe(false);

    process.env.TRUST_E2E_AUTOCONFIRM = '0';
    resetConfigForTest();
    expect(getConfig().TRUST_E2E_AUTOCONFIRM).toBe(false);
  });
});

describe('production secret-strength guard', () => {
  const STRONG_SESSION = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4';
  const STRONG_ADMIN = 'f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3';

  beforeEach(() => {
    setTestEnv();
    // Strong baseline so only the secret under test triggers a failure;
    // resend so the EMAIL_PROVIDER guard doesn't fire.
    process.env.TRUST_SESSION_SECRET = STRONG_SESSION;
    process.env.TRUST_ADMIN_SECRET = STRONG_ADMIN;
    process.env.EMAIL_PROVIDER = 'resend';
    resetConfigForTest();
  });
  afterEach(() => {
    delete process.env.NODE_ENV;
    delete process.env.EMAIL_PROVIDER;
    resetConfigForTest();
  });

  it('refuses to boot in production with the published placeholder session secret', () => {
    process.env.NODE_ENV = 'production';
    process.env.TRUST_SESSION_SECRET = 'replace-me-with-a-long-random-string';
    resetConfigForTest();
    expect(() => getConfig()).toThrow(/TRUST_SESSION_SECRET/);
  });

  it('refuses to boot in production with a placeholder admin secret', () => {
    process.env.NODE_ENV = 'production';
    process.env.TRUST_ADMIN_SECRET = 'replace-me-with-a-long-random-string';
    resetConfigForTest();
    expect(() => getConfig()).toThrow(/TRUST_ADMIN_SECRET/);
  });

  it('refuses to boot in production with a sub-32-char admin secret', () => {
    process.env.NODE_ENV = 'production';
    process.env.TRUST_ADMIN_SECRET = 'short-admin-1234'; // 16 chars, passes min(16)
    resetConfigForTest();
    expect(() => getConfig()).toThrow(/TRUST_ADMIN_SECRET/);
  });

  it('boots in production with strong, non-placeholder secrets', () => {
    process.env.NODE_ENV = 'production';
    resetConfigForTest();
    expect(() => getConfig()).not.toThrow();
  });

  it('allows short/placeholder secrets outside production (dev/test convenience)', () => {
    process.env.NODE_ENV = 'test';
    process.env.TRUST_SESSION_SECRET = 'replace-me-with-a-long-random-string';
    process.env.TRUST_ADMIN_SECRET = 'short-admin-1234';
    resetConfigForTest();
    expect(() => getConfig()).not.toThrow();
  });
});

describe('EMAIL_PROVIDER production guard', () => {
  beforeEach(() => {
    setTestEnv();
    process.env.TRUST_SESSION_SECRET = 'a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4';
    process.env.TRUST_ADMIN_SECRET = 'f0e1d2c3b4a5968778695a4b3c2d1e0ff0e1d2c3';
    resetConfigForTest();
  });
  afterEach(() => {
    delete process.env.NODE_ENV;
    delete process.env.EMAIL_PROVIDER;
    resetConfigForTest();
  });

  it('refuses to boot in production with EMAIL_PROVIDER=stdout', () => {
    process.env.NODE_ENV = 'production';
    process.env.EMAIL_PROVIDER = 'stdout';
    resetConfigForTest();
    expect(() => getConfig()).toThrow(/EMAIL_PROVIDER/);
  });

  it('boots in production with a real email provider', () => {
    process.env.NODE_ENV = 'production';
    process.env.EMAIL_PROVIDER = 'resend';
    resetConfigForTest();
    expect(() => getConfig()).not.toThrow();
  });

  it('allows EMAIL_PROVIDER=stdout outside production', () => {
    process.env.NODE_ENV = 'development';
    process.env.EMAIL_PROVIDER = 'stdout';
    resetConfigForTest();
    expect(getConfig().EMAIL_PROVIDER).toBe('stdout');
  });
});
