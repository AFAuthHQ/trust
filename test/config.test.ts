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
    process.env.NODE_ENV = 'production';
    delete process.env.TRUST_E2E_AUTOCONFIRM;
    resetConfigForTest();
    expect(getConfig().TRUST_E2E_AUTOCONFIRM).toBe(false);

    process.env.TRUST_E2E_AUTOCONFIRM = '0';
    resetConfigForTest();
    expect(getConfig().TRUST_E2E_AUTOCONFIRM).toBe(false);
  });
});
