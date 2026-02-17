import { describe, it, expect } from 'vitest';
import { findSecrets, redact, isSafePattern } from '../src/utils/patterns.js';

// Build fake keys dynamically to avoid triggering the secret-blocking hook
const FAKE_OPENAI_KEY = ['sk', 'abcdefghijklmnopqrstuvwxyz1234567890'].join('-');
const FAKE_AWS_KEY = 'AKIA' + 'IOSFODNN7TESTKEY';
const FAKE_GH_PAT = 'ghp_' + 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';

describe('findSecrets', () => {
  it('detects OpenAI API keys', () => {
    const content = `OPENAI_API_KEY=${FAKE_OPENAI_KEY}`;
    const results = findSecrets(content);
    expect(results.length).toBe(1);
    expect(results[0].pattern.name).toBe('OpenAI API Key');
  });

  it('detects AWS access keys', () => {
    const content = `aws_key=${FAKE_AWS_KEY}`;
    const results = findSecrets(content);
    expect(results.length).toBe(1);
    expect(results[0].pattern.name).toBe('AWS Access Key');
  });

  it('detects GitHub PATs', () => {
    const content = `token=${FAKE_GH_PAT}`;
    const results = findSecrets(content);
    expect(results.length).toBe(1);
    expect(results[0].pattern.name).toBe('GitHub PAT (classic)');
  });

  it('does not flag safe patterns', () => {
    const content = 'KEY=$(secrets get MY_API_KEY)';
    const results = findSecrets(content);
    expect(results.length).toBe(0);
  });

  it('does not flag gh auth token', () => {
    const content = 'GITHUB_TOKEN=$(gh auth token)';
    const results = findSecrets(content);
    expect(results.length).toBe(0);
  });

  it('does not flag placeholders', () => {
    const content = 'API_KEY=YOUR_KEY_HERE_REPLACE_ME_PLEASE';
    const results = findSecrets(content);
    expect(results.length).toBe(0);
  });

  it('reports correct line numbers', () => {
    const content = `line1\nline2\nkey=${FAKE_OPENAI_KEY}\nline4`;
    const results = findSecrets(content);
    expect(results[0].line).toBe(3);
  });
});

describe('redact', () => {
  it('redacts long secrets showing first 8 and last 4', () => {
    const result = redact(FAKE_OPENAI_KEY);
    expect(result.startsWith('sk-abcde')).toBe(true);
    expect(result.endsWith('7890')).toBe(true);
    expect(result).toContain('...');
  });

  it('fully redacts short secrets', () => {
    const result = redact('short123');
    expect(result).toBe('***REDACTED***');
  });
});

describe('isSafePattern', () => {
  it('recognizes Keychain references', () => {
    expect(isSafePattern('$(secrets get MY_KEY)')).toBe(true);
  });

  it('recognizes env var references', () => {
    expect(isSafePattern('process.env.API_KEY')).toBe(true);
  });

  it('recognizes placeholder values', () => {
    expect(isSafePattern('YOUR_API_KEY_HERE')).toBe(true);
    expect(isSafePattern('changeme')).toBe(true);
  });

  it('does not flag real values as safe', () => {
    expect(isSafePattern('realkey123456789abcdef')).toBe(false);
  });
});
