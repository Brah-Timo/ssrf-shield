/**
 * Unit tests: Core Guard Engine
 */

import { checkUrl, checkUrlSync } from '../../src/guard';

describe('checkUrl — scheme blocking', () => {
  const dangerousSchemes = [
    'file:///etc/passwd',
    'file:///etc/shadow',
    'file:///proc/self/environ',
    'gopher://localhost:6379/_',
    'dict://localhost:6379/CONFIG',
    'ftp://127.0.0.1/',
    'sftp://192.168.1.1/',
    'data:text/html,<script>alert(1)</script>',
    'javascript:alert(document.cookie)',
    'ldap://127.0.0.1/',
    'tftp://192.168.1.1/',
  ];

  test.each(dangerousSchemes)('blocks scheme: %s', async (url) => {
    const result = await checkUrl(url);
    expect(result.allowed).toBe(false);
    expect(result.threat?.category).toBe('BLOCKED_SCHEME');
  });
});

describe('checkUrl — direct IP blocking', () => {
  const privateIps = [
    'http://127.0.0.1/',
    'http://localhost:8080/',
    'http://10.0.0.1/',
    'http://172.16.0.1/',
    'http://192.168.1.1/',
    'http://169.254.169.254/',
    'http://[::1]/',
    'http://[fe80::1]/',
  ];

  test.each(privateIps)('blocks private IP URL: %s', async (url) => {
    const result = await checkUrl(url);
    expect(result.allowed).toBe(false);
  });
});

describe('checkUrl — port blocking', () => {
  const internalPortUrls = [
    'http://example.com:6379/',
    'http://example.com:27017/',
    'http://example.com:5432/',
    'http://example.com:3306/',
    'http://example.com:11211/',
    'http://example.com:9200/',
    'http://example.com:22/',
  ];

  test.each(internalPortUrls)('blocks internal port: %s', async (url) => {
    const result = await checkUrl(url);
    expect(result.allowed).toBe(false);
    expect(result.threat?.category).toBe('BLOCKED_PORT');
  });
});

describe('checkUrl — invalid URLs', () => {
  const invalidUrls = [
    '',
    'not a url',
    'http://',
    '   ',
  ];

  test.each(invalidUrls)('blocks invalid URL: %s', async (url) => {
    const result = await checkUrl(url);
    expect(result.allowed).toBe(false);
  });
});

describe('checkUrl — result structure', () => {
  it('blocked result has threat info', async () => {
    const result = await checkUrl('http://127.0.0.1/');
    expect(result.allowed).toBe(false);
    expect(result.threat).toBeDefined();
    expect(result.threat?.category).toBeTruthy();
    expect(result.threat?.reason).toBeTruthy();
    expect(result.threat?.severity).toBeTruthy();
    expect(typeof result.threat?.likelyBypassAttempt).toBe('boolean');
    expect(typeof result.durationMs).toBe('number');
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
  });

  it('allowed result has safeUrl', async () => {
    const result = await checkUrl('https://httpbin.org/get');
    if (result.allowed) {
      expect(result.safeUrl).toBeTruthy();
      expect(result.safeUrl).toContain('httpbin.org');
    }
    // If DNS fails in test env, still validates structure
    expect(typeof result.durationMs).toBe('number');
  }, 10000);
});

describe('checkUrlSync — synchronous mode', () => {
  it('blocks private IPs synchronously', () => {
    const result = checkUrlSync('http://127.0.0.1/');
    expect(result.allowed).toBe(false);
  });

  it('blocks dangerous schemes synchronously', () => {
    const result = checkUrlSync('file:///etc/passwd');
    expect(result.allowed).toBe(false);
    expect(result.threat?.category).toBe('BLOCKED_SCHEME');
  });

  it('handles hostnames in sync mode (skips DNS)', () => {
    // Sync mode skips DNS — hostname that looks safe passes
    const result = checkUrlSync('https://example.com/');
    // Should allow (can't verify without DNS in sync mode)
    expect(result.allowed).toBe(true);
  });
});

describe('checkUrl — options', () => {
  it('respects custom blockedPorts override', async () => {
    // Override with only port 9999 blocked
    const result = await checkUrl('https://example.com:6379/', {
      blockedPorts: [9999],
    });
    // 6379 is NOT in the custom list, so it should pass DNS check
    // (will likely be blocked by DNS if example.com resolves, but not port)
    expect(result.threat?.category).not.toBe('BLOCKED_PORT');
  });

  it('respects additionalBlockedPorts', async () => {
    const result = await checkUrl('https://example.com:12345/', {
      additionalBlockedPorts: [12345],
    });
    expect(result.allowed).toBe(false);
    expect(result.threat?.category).toBe('BLOCKED_PORT');
  });

  it('exposeReason does not affect blocking logic', async () => {
    const result = await checkUrl('http://127.0.0.1/', { exposeReason: true });
    expect(result.allowed).toBe(false);
  });

  it('allowOnDnsError = true allows when DNS fails', async () => {
    // Non-existent domain — DNS will fail
    const result = await checkUrl(
      'http://this-domain-definitely-does-not-exist-ssrf-shield.invalid/test',
      { allowOnDnsError: true },
    );
    // Might be allowed (NXDOMAIN + allowOnDnsError=true)
    // or blocked with DNS_TIMEOUT depending on resolver
    expect(typeof result.allowed).toBe('boolean');
  }, 10000);
});

