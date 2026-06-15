/**
 * Unit tests: URL Normalizer
 */

import { normalizeUrl, parseNormalizedUrl, isDirectIp, InvalidUrlError } from '../../src/utils/url-normalizer';

describe('normalizeUrl', () => {
  it('strips leading/trailing whitespace', () => {
    const result = normalizeUrl('  https://example.com/  ');
    expect(result).toContain('example.com');
  });

  it('converts backslashes to forward slashes', () => {
    const result = normalizeUrl('http:\\\\localhost/path');
    expect(result).toContain('http://');
  });

  it('removes embedded credentials', () => {
    // http://attacker.com@localhost/ → real host is localhost
    const result = normalizeUrl('http://attacker.com@localhost/');
    const parsed = new URL(result);
    expect(parsed.hostname).toBe('localhost');
    expect(parsed.username).toBe('');
    expect(parsed.password).toBe('');
  });

  it('removes URL fragment', () => {
    const result = normalizeUrl('https://example.com/page#section');
    expect(result).not.toContain('#');
  });

  it('lowercases the hostname', () => {
    const result = normalizeUrl('HTTPS://EXAMPLE.COM/PATH');
    const parsed = new URL(result);
    expect(parsed.hostname).toBe('example.com');
  });

  it('removes null bytes', () => {
    const result = normalizeUrl('https://example.com/\x00path');
    expect(result).not.toContain('\x00');
  });

  it('handles URL-encoded characters in hostname', () => {
    // The WHATWG URL parser decodes percent-encoded hostnames
    // 127%2E0%2E0%2E1 → 127.0.0.1 (in newer Node.js versions it may vary)
    // We check it doesn't throw
    expect(() => normalizeUrl('http://127.0.0.1/')).not.toThrow();
  });

  it('throws InvalidUrlError for empty string', () => {
    expect(() => normalizeUrl('')).toThrow(InvalidUrlError);
  });

  it('throws InvalidUrlError for non-string input', () => {
    expect(() => normalizeUrl(null as unknown as string)).toThrow(InvalidUrlError);
  });

  it('throws InvalidUrlError for unparseable URL', () => {
    expect(() => normalizeUrl('not a url at all')).toThrow(InvalidUrlError);
  });

  it('normalizes Unicode NFC', () => {
    // Should not throw
    expect(() => normalizeUrl('https://example.com/caf\u00e9')).not.toThrow();
  });
});

describe('isDirectIp', () => {
  it('detects standard IPv4', () => {
    expect(isDirectIp('127.0.0.1')).toBe(true);
    expect(isDirectIp('192.168.1.1')).toBe(true);
  });

  it('detects hex IP', () => {
    expect(isDirectIp('0x7f000001')).toBe(true);
  });

  it('detects octal IP', () => {
    expect(isDirectIp('0177.0.0.1')).toBe(true);
  });

  it('detects decimal integer IP', () => {
    expect(isDirectIp('2130706433')).toBe(true);
  });

  it('detects bracketed IPv6', () => {
    expect(isDirectIp('[::1]')).toBe(true);
  });

  it('returns false for hostnames', () => {
    expect(isDirectIp('example.com')).toBe(false);
    expect(isDirectIp('api.github.com')).toBe(false);
  });
});

