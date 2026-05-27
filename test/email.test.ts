import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { setTestEnv } from './helpers.js';
import { sendMagicLink } from '../src/lib/verification/email.js';
import { resetConfigForTest } from '../src/lib/config.js';

const originalFetch = globalThis.fetch;

describe('sendMagicLink — Resend provider', () => {
  beforeEach(() => {
    setTestEnv();
    resetConfigForTest();
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    delete process.env.EMAIL_API_KEY;
    process.env.EMAIL_PROVIDER = 'stdout';
    resetConfigForTest();
  });

  it('posts to api.resend.com with the configured key and from address', async () => {
    process.env.EMAIL_PROVIDER = 'resend';
    process.env.EMAIL_API_KEY = 're_test_key_12345';
    process.env.EMAIL_FROM = 'no-reply@trust.afauth.org';
    resetConfigForTest();

    let captured: { url: string; init: RequestInit } | undefined;
    globalThis.fetch = (async (input, init) => {
      captured = { url: String(input), init: init ?? {} };
      return new Response('{"id":"em_1"}', {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    }) as typeof globalThis.fetch;

    await sendMagicLink({
      to: 'human@example.com',
      link: 'https://trust.afauth.org/signin/callback?token=abc',
    });

    expect(captured?.url).toBe('https://api.resend.com/emails');
    const headers = captured!.init.headers as Record<string, string>;
    expect(headers.authorization).toBe('Bearer re_test_key_12345');
    expect(headers['content-type']).toBe('application/json');
    const body = JSON.parse(captured!.init.body as string) as {
      from: string; to: string; subject: string; text: string; html: string;
    };
    expect(body.from).toBe('no-reply@trust.afauth.org');
    expect(body.to).toBe('human@example.com');
    expect(body.subject).toContain('Sign in');
    expect(body.text).toContain('https://trust.afauth.org/signin/callback?token=abc');
    expect(body.html).toContain('Sign in');
    expect(body.html).toContain('https://trust.afauth.org/signin/callback?token=abc');
  });

  it('surfaces Resend errors with the response detail', async () => {
    process.env.EMAIL_PROVIDER = 'resend';
    process.env.EMAIL_API_KEY = 're_test';
    resetConfigForTest();

    globalThis.fetch = (async () =>
      new Response(JSON.stringify({ message: 'invalid_api_key' }), {
        status: 401,
        headers: { 'content-type': 'application/json' },
      })) as typeof globalThis.fetch;

    await expect(
      sendMagicLink({ to: 'a@b.com', link: 'https://x' }),
    ).rejects.toThrow(/resend.*invalid_api_key/i);
  });

  it('refuses when EMAIL_API_KEY is missing for a non-stdout provider', async () => {
    process.env.EMAIL_PROVIDER = 'resend';
    delete process.env.EMAIL_API_KEY;
    resetConfigForTest();

    await expect(
      sendMagicLink({ to: 'a@b.com', link: 'https://x' }),
    ).rejects.toThrow(/EMAIL_API_KEY required/);
  });
});
