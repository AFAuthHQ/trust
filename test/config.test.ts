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
