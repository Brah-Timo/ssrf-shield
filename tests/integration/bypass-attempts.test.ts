/**
 * Integration tests: SSRF Bypass Attempts
 * ─────────────────────────────────────────
 * Comprehensive test suite covering 80+ known SSRF bypass techniques.
 *
 * Sources:
 *  - OWASP SSRF Prevention Cheat Sheet
 *  - PayloadsAllTheThings SSRF section
 *  - HackTricks: SSRF (Server Side Request Forgery)
 *  - Orange Tsai: "A New Era of SSRF" (BlackHat 2017)
 *  - portswigger: Server-side request forgery (SSRF)
 *
 * ALL entries in the "blocked" sections MUST return allowed=false.
 * ALL entries in "safe" sections MUST return allowed=true.
 */

import { checkUrl } from '../../src/guard';

// Helper: run checkUrl and return allowed boolean
async function blocked(url: string): Promise<boolean> {
  const result = await checkUrl(url);
  return !result.allowed;
}

async function allowed(url: string): Promise<boolean> {
  const result = await checkUrl(url);
  return result.allowed;
}

// ══════════════════════════════════════════════════════════════════════════════
// BLOCKED: Localhost / Loopback variations
// ══════════════════════════════════════════════════════════════════════════════
describe('BLOCKED: Localhost variations', () => {
  const cases = [
    'http://localhost/',
    'http://localhost:80/',
    'http://localhost:443/',
    'http://127.0.0.1/',
    'http://127.0.0.1:80/',
    'http://127.1/',
    'http://127.0.1/',
    'http://127.000.000.001/',
    'http://0/',
    'http://0.0.0.0/',
    'http://[::1]/',
    'http://[0:0:0:0:0:0:0:1]/',
    'http://[0000:0000:0000:0000:0000:0000:0000:0001]/',
  ];

  test.each(cases)('blocks: %s', async (url) => {
    expect(await blocked(url)).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCKED: IP Encoding bypasses
// ══════════════════════════════════════════════════════════════════════════════
describe('BLOCKED: IP encoding tricks', () => {
  const cases = [
    'http://2130706433/',        // 127.0.0.1 decimal
    'http://0x7f000001/',        // 127.0.0.1 hex
    'http://0177.0.0.1/',        // 127.0.0.1 octal first octet
    'http://0177.0000.0000.0001/', // octal all octets
    'http://0xC0A80101/',        // 192.168.1.1 hex
    'http://3232235777/',        // 192.168.1.1 decimal
  ];

  test.each(cases)('blocks: %s', async (url) => {
    expect(await blocked(url)).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCKED: Cloud Metadata endpoints
// ══════════════════════════════════════════════════════════════════════════════
describe('BLOCKED: Cloud metadata endpoints', () => {
  const cases = [
    'http://169.254.169.254/',                        // AWS/Azure/GCP/DO IMDS
    'http://169.254.169.254/latest/meta-data/',       // AWS IMDS v1
    'http://169.254.169.254/latest/meta-data/iam/',   // AWS IAM creds!
    'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
    'http://169.254.169.254/latest/user-data',        // AWS user-data
    'http://169.254.170.2/',                          // AWS ECS metadata
    'http://169.254.169.254/metadata/v1/',            // Azure IMDS
    'http://100.100.100.200/',                        // Alibaba Cloud
    'http://169.254.169.254/computeMetadata/v1/',     // GCP IMDS
  ];

  test.each(cases)('blocks: %s', async (url) => {
    expect(await blocked(url)).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCKED: RFC1918 Private IP ranges
// ══════════════════════════════════════════════════════════════════════════════
describe('BLOCKED: RFC1918 private ranges', () => {
  const cases = [
    'http://10.0.0.1/',
    'http://10.10.10.10/',
    'http://10.255.255.255/',
    'http://172.16.0.1/',
    'http://172.16.100.200/',
    'http://172.31.255.255/',
    'http://192.168.0.1/',
    'http://192.168.1.100/',
    'http://192.168.255.255/',
    'http://192.168.1.1/admin',
    'http://192.168.1.1/internal/api',
  ];

  test.each(cases)('blocks: %s', async (url) => {
    expect(await blocked(url)).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCKED: Dangerous schemes/protocols
// ══════════════════════════════════════════════════════════════════════════════
describe('BLOCKED: Dangerous schemes', () => {
  const cases = [
    // File system reads
    'file:///etc/passwd',
    'file:///etc/shadow',
    'file:///etc/hosts',
    'file:///proc/self/environ',
    'file:///proc/self/cmdline',
    'file:///proc/net/tcp',
    'file:///var/run/secrets/kubernetes.io/serviceaccount/token',
    'file://localhost/etc/passwd',

    // Gopher — raw TCP, can speak Redis/SMTP/memcached
    'gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a',
    'gopher://127.0.0.1:6379/_PING',
    'gopher://localhost:25/xHELO%20attacker.com',

    // Dictionary protocol — port enumeration
    'dict://localhost:6379/CONFIG',
    'dict://127.0.0.1:11211/',

    // FTP
    'ftp://127.0.0.1/',
    'ftp://192.168.1.1/',
    'ftps://localhost/',

    // Data URI
    'data:text/html,<script>alert(1)</script>',
    'data:application/json,{"key":"value"}',
    'data:text/plain,/etc/passwd contents',

    // JavaScript
    'javascript:alert(document.domain)',
    'javascript:fetch("http://169.254.169.254")',

    // LDAP
    'ldap://127.0.0.1/',
    'ldap://localhost:389/',

    // SFTP / TFTP
    'sftp://192.168.1.1/',
    'tftp://192.168.1.1/',
  ];

  test.each(cases)('blocks: %s', async (url) => {
    expect(await blocked(url)).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCKED: IPv6 variations
// ══════════════════════════════════════════════════════════════════════════════
describe('BLOCKED: IPv6 private/loopback', () => {
  const cases = [
    'http://[::1]/',
    'http://[fe80::1]/',
    'http://[fe80::1%25eth0]/',   // zone ID
    'http://[fc00::1]/',
    'http://[fd00::1]/',
    'http://[::ffff:127.0.0.1]/', // IPv4-mapped
    'http://[::ffff:7f00:1]/',    // IPv4-mapped hex
    'http://[0:0:0:0:0:ffff:127.0.0.1]/', // full IPv4-mapped
    'http://[::ffff:169.254.169.254]/',    // AWS IMDS via IPv6
  ];

  test.each(cases)('blocks: %s', async (url) => {
    expect(await blocked(url)).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCKED: Internal service ports (on external-looking domains)
// ══════════════════════════════════════════════════════════════════════════════
describe('BLOCKED: Internal service ports', () => {
  const cases = [
    ['http://example.com:22/', 'SSH'],
    ['http://example.com:23/', 'Telnet'],
    ['http://example.com:25/', 'SMTP'],
    ['http://example.com:6379/', 'Redis'],
    ['http://example.com:11211/', 'Memcached'],
    ['http://example.com:27017/', 'MongoDB'],
    ['http://example.com:5432/', 'PostgreSQL'],
    ['http://example.com:3306/', 'MySQL'],
    ['http://example.com:9200/', 'Elasticsearch'],
    ['http://example.com:2379/', 'etcd'],
    ['http://example.com:8500/', 'Consul'],
    ['http://example.com:10250/', 'Kubernetes Kubelet'],
    ['http://example.com:2375/', 'Docker API'],
  ];

  test.each(cases)('blocks %s (%s)', async ([url]) => {
    expect(await blocked(url!)).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCKED: URL structure attacks
// ══════════════════════════════════════════════════════════════════════════════
describe('BLOCKED: URL structure attacks', () => {
  it('blocks credentials-in-URL bypass: http://attacker@127.0.0.1/', async () => {
    // The real host here is 127.0.0.1, not "attacker"
    expect(await blocked('http://attacker@127.0.0.1/')).toBe(true);
  });

  it('blocks credentials-in-URL bypass: http://legit.com@192.168.1.1/', async () => {
    expect(await blocked('http://legit.com@192.168.1.1/')).toBe(true);
  });

  it('blocks empty URL', async () => {
    expect(await blocked('')).toBe(true);
  });

  it('blocks just a path', async () => {
    expect(await blocked('/etc/passwd')).toBe(true);
  });

  it('blocks URL with no hostname', async () => {
    expect(await blocked('http://')).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// BLOCKED: Other reserved/special ranges
// ══════════════════════════════════════════════════════════════════════════════
describe('BLOCKED: Reserved/special IP ranges', () => {
  const cases = [
    'http://0.0.0.0/',
    'http://100.64.0.1/',    // Shared address space (RFC6598)
    'http://192.0.2.1/',     // TEST-NET-1 (documentation)
    'http://198.51.100.1/',  // TEST-NET-2
    'http://203.0.113.1/',   // TEST-NET-3
    'http://224.0.0.1/',     // Multicast
    'http://255.255.255.255/',  // Broadcast
  ];

  test.each(cases)('blocks: %s', async (url) => {
    expect(await blocked(url)).toBe(true);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// ALLOWED: Safe public URLs — these MUST pass
// ══════════════════════════════════════════════════════════════════════════════
describe('ALLOWED: Safe public URLs', () => {
  const cases = [
    'https://api.github.com/users/octocat',
    'https://httpbin.org/get',
    'https://jsonplaceholder.typicode.com/posts/1',
    'https://registry.npmjs.org/express',
    'https://cdn.jsdelivr.net/npm/axios/dist/axios.min.js',
    'http://example.com/',
    'http://example.org/path',
    'https://example.com:443/api',
    'http://example.com:80/api',
  ];

  test.each(cases)('allows: %s', async (url) => {
    const result = await checkUrl(url);
    // Allowed if either: allowed=true OR blocked by DNS (test environment may not resolve)
    // We check it's not blocked by our STATIC checks (IP/scheme/port)
    if (!result.allowed) {
      expect(['DNS_RESOLVED_PRIVATE', 'DNS_ERROR', 'DNS_TIMEOUT']).toContain(
        result.threat?.category,
      );
    }
  }, 15000);
});

// ══════════════════════════════════════════════════════════════════════════════
// THREAT METADATA: Verify threat info structure
// ══════════════════════════════════════════════════════════════════════════════
describe('Threat metadata accuracy', () => {
  it('cloud metadata has critical severity', async () => {
    const result = await checkUrl('http://169.254.169.254/');
    expect(result.allowed).toBe(false);
    expect(result.threat?.severity).toBe('critical');
  });

  it('loopback has critical severity', async () => {
    const result = await checkUrl('http://127.0.0.1/');
    expect(result.allowed).toBe(false);
    expect(result.threat?.severity).toBe('critical');
  });

  it('encoded IP is blocked (hex encoding)', async () => {
    const result = await checkUrl('http://0x7f000001/');
    expect(result.allowed).toBe(false);
    // wasEncoded=true → either likelyBypassAttempt=true or category indicates it
    expect(result.threat).toBeDefined();
  });

  it('blocked result includes reason string', async () => {
    const result = await checkUrl('http://192.168.1.1/');
    expect(result.allowed).toBe(false);
    expect(result.threat?.reason).toBeTruthy();
    expect(result.threat?.reason.length).toBeGreaterThan(10);
  });

  it('durationMs is a non-negative number', async () => {
    const result = await checkUrl('http://127.0.0.1/');
    expect(result.durationMs).toBeGreaterThanOrEqual(0);
    expect(typeof result.durationMs).toBe('number');
  });
});

