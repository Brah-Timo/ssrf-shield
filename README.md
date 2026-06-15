# 🛡️ ssrf-shield

**Block SSRF attacks in one line. Production-ready middleware for Express, Fastify, Hono, and any Node.js application.**

[![npm version](https://badge.fury.io/js/ssrf-shield.svg)](https://badge.fury.io/js/ssrf-shield)
[![Downloads](https://img.shields.io/npm/dm/ssrf-shield.svg)](https://www.npmjs.com/package/ssrf-shield)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue.svg)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green.svg)](https://nodejs.org/)
[![OWASP](https://img.shields.io/badge/OWASP-Top10%20A10-red.svg)](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)

---

## What is SSRF?

**Server-Side Request Forgery (SSRF)** — OWASP Top 10 #A10:2021.

When your app fetches a URL provided by a user, an attacker can send:
```
http://169.254.169.254/latest/meta-data/iam/security-credentials/
```
…and your server fetches it with full IAM permissions, leaking AWS credentials.

**Real damage**: The 2019 Capital One breach (106 million records) was caused by SSRF against AWS IMDS.

---

## Installation

```bash
npm install ssrf-shield
```

**Requirements**: Node.js ≥ 18.0.0, TypeScript ≥ 5.0 (optional)

---

## Quick Start — One Line

```typescript
import express from 'express';
import { ssrfGuard } from 'ssrf-shield';

const app = express();

app.get('/fetch', ssrfGuard(), async (req, res) => {
  //                ^^^^^^^^^^^
  //                That's it. Private IPs, gopher, file://, IMDS — all blocked.
  
  const data = await fetch(req.ssrfGuard!.safeUrl);  // use normalized URL
  res.json(await data.json());
});
```

---

## Framework Examples

### Express
```typescript
import { ssrfGuard } from 'ssrf-shield';

// Single route
app.get('/proxy', ssrfGuard(), handler);

// Custom URL parameter name
app.get('/fetch', ssrfGuard({ urlParam: 'target' }), handler);

// Global middleware (checks every request with a 'url' param)
app.use(ssrfGuard());
```

### Fastify
```typescript
import { ssrfGuardFastify } from 'ssrf-shield';

fastify.addHook('preHandler', ssrfGuardFastify());
```

### Any framework / raw fetch wrapper
```typescript
import { checkUrl } from 'ssrf-shield';

async function safeFetch(userUrl: string) {
  const result = await checkUrl(userUrl);
  
  if (!result.allowed) {
    throw new Error(`Blocked [${result.threat?.category}]: ${result.threat?.reason}`);
  }
  
  return fetch(result.safeUrl!);  // safeUrl is normalized
}
```

---

## What Gets Blocked ✅

| Attack | Example | Category |
|--------|---------|----------|
| Loopback | `http://127.0.0.1/` | `LOOPBACK` |
| Localhost | `http://localhost:6379/` | `LOOPBACK` |
| AWS IMDS | `http://169.254.169.254/latest/meta-data/iam/` | `CLOUD_METADATA` |
| GCP metadata | `http://metadata.google.internal/` | `CLOUD_METADATA_HOSTNAME` |
| Azure IMDS | `http://169.254.169.254/metadata/v1/` | `CLOUD_METADATA` |
| RFC1918 | `http://192.168.1.1/admin` | `PRIVATE_IP` |
| IPv6 loopback | `http://[::1]/` | `LOOPBACK` |
| IPv4-mapped IPv6 | `http://[::ffff:127.0.0.1]/` | `IPV6_MAPPED_IPV4` |
| Hex IP bypass | `http://0x7f000001/` | `LOOPBACK` |
| Octal IP bypass | `http://0177.0.0.1/` | `LOOPBACK` |
| Decimal IP | `http://2130706433/` | `LOOPBACK` |
| Gopher/Redis | `gopher://localhost:6379/_FLUSHALL` | `BLOCKED_SCHEME` |
| File reads | `file:///etc/passwd` | `BLOCKED_SCHEME` |
| Internal ports | `http://example.com:6379/` | `BLOCKED_PORT` |
| DNS rebinding | `evil.com → 127.0.0.1` | `DNS_RESOLVED_PRIVATE` |
| CGN range | `http://100.64.0.1/` | `SHARED_ADDRESS_SPACE` |

---

## Response Format

Blocked requests return:
```json
{
  "error": "SSRF_BLOCKED",
  "message": "Request blocked by ssrf-shield",
  "code": "CLOUD_METADATA"
}
```

With `exposeReason: true`:
```json
{
  "error": "SSRF_BLOCKED",
  "message": "Cloud metadata endpoint blocked: 169.254.169.254",
  "code": "CLOUD_METADATA",
  "severity": "critical",
  "likelyBypassAttempt": false
}
```

---

## Guard Result (for `checkUrl`)

```typescript
interface GuardResult {
  allowed: boolean;
  safeUrl?: string;           // normalized URL (only when allowed=true)
  threat?: {
    category: ThreatCategory; // e.g. 'CLOUD_METADATA', 'LOOPBACK'
    reason: string;           // human-readable explanation
    severity: 'critical' | 'high' | 'medium' | 'low';
    likelyBypassAttempt: boolean;
    blockedValue?: string;    // the IP that triggered the block
    matchedRange?: string;    // the CIDR range that matched
  };
  durationMs: number;         // time taken (ms)
  resolvedIps?: string[];     // DNS-resolved IPs (if applicable)
}
```

---

## Security Architecture

```
User Input URL
     │
     ▼
┌─────────────────────────────────┐
│ 1. URL Normalization             │  Strip tricks: backslash, null bytes,
│    url-normalizer.ts             │  credentials, Unicode, tab/newline
└─────────────┬───────────────────┘
              ▼
┌─────────────────────────────────┐
│ 2. Scheme Validation             │  Block: file, gopher, dict, ftp,
│    dangerous-schemes.ts          │  data, javascript, ldap, sftp, +30 more
└─────────────┬───────────────────┘
              ▼
┌─────────────────────────────────┐
│ 3. Port Validation               │  Block: 6379 (Redis), 27017 (MongoDB),
│    protocol-validator.ts         │  5432 (PostgreSQL), 2375 (Docker), +30 more
└─────────────┬───────────────────┘
              ▼
┌─────────────────────────────────┐
│ 4. IP Validation                 │  Block all: loopback, RFC1918,
│    ip-validator.ts               │  link-local, IPv6 private, cloud metadata
│    ip-parser.ts (hex/oct/dec)    │  Handles ALL encoding tricks
└─────────────┬───────────────────┘
              ▼
┌─────────────────────────────────┐
│ 5. DNS Resolution                │  Resolve A + AAAA records, check ALL IPs
│    dns-resolver.ts               │  DNS timeout = fail-safe block
└─────────────┬───────────────────┘
              ▼
         ALLOWED ✅
     (normalized safeUrl)
```

---

## Pro Plan — $29/month

```typescript
app.use(ssrfGuard({
  proLicense: process.env.SSRF_GUARD_KEY,
  
  // ✅ Trust specific internal hosts
  allowlist: ['api.myservice.com', '*.internal.corp', '10.0.0.0/8'],
  
  // ✅ Real-time attack callbacks
  onBlock: async (event) => {
    await slack.send(`SSRF [${event.severity}]: ${event.url} from ${event.ip}`);
  },
}));
```

**Pro Features:**

| Feature | Description |
|---------|-------------|
| **Custom Allowlist** | Bypass checks for trusted internal APIs |
| **Event Callbacks** | `onBlock` / `onAllow` for custom logging |
| **Structured Logger** | Batched event shipping to Pro Dashboard |
| **Webhook Alerts** | Slack / PagerDuty / Discord / custom HTTP |
| **Rate Limiting** | Per-IP request limiting |
| **Attack Dashboard** | Geographic map, trends, top attackers |
| **Priority Support** | Direct email/Slack support |

👉 **[Get Pro at ssrf-shield.io](https://ssrf-shield.io/pro)**

---

## Configuration Reference

| Option | Default | Description |
|--------|---------|-------------|
| `urlParam` | `'url'` | Query/body param name containing the URL |
| `blockedPorts` | (35 ports) | Override blocked ports list entirely |
| `additionalBlockedPorts` | `[]` | Add to the default blocked ports |
| `dnsTimeoutMs` | `3000` | DNS timeout in ms (fail-safe on timeout) |
| `allowOnDnsError` | `false` | Allow when DNS fails (fail-open) |
| `exposeReason` | `false` | Include reason in HTTP response |
| `blockedStatusCode` | `403` | HTTP status for blocked requests |
| `skipDnsResolution` | `false` | Skip DNS (only for direct-IP inputs) |

---

## Performance

- **Direct IP check**: ~0.1ms (pure in-memory, no I/O)
- **DNS check**: ~3–15ms (network dependent)
- **Zero impact** on requests that don't have the URL parameter
- **Async**: DNS resolution is non-blocking

---

## Advanced Usage

### Low-Level API

```typescript
import {
  checkIpAddress,     // check a single IP
  resolveAndCheckDns, // resolve + check hostname
  normalizeUrl,       // just normalize a URL
  isBlockedIp,        // quick boolean check
} from 'ssrf-shield';

// Check a single IP
const ipResult = checkIpAddress('169.254.169.254');
// { blocked: true, threatCategory: 'CLOUD_METADATA', canonicalIp: '169.254.169.254' }

// Resolve and check a hostname
const dnsResult = await resolveAndCheckDns('api.github.com');
// { safe: true, resolvedIps: ['140.82.121.6'] }
```

### TypeScript Types

```typescript
import type {
  SsrfGuardOptions,
  GuardResult,
  BlockEvent,
  AllowEvent,
  ThreatCategory,
  ThreatInfo,
} from 'ssrf-shield';
```

---

## Testing

```bash
npm test                    # All tests with coverage
npm run test:unit           # Unit tests only
npm run test:bypass         # 80+ bypass attempt tests
npm run test:integration    # Express middleware tests
```

---

## Comparison

| Feature | ssrf-shield | naive-ip-check | url-filter |
|---------|:----------:|:--------------:|:----------:|
| TypeScript-first | ✅ | ❌ | ⚠️ |
| IPv6 + IPv4-mapped | ✅ | ❌ | ❌ |
| Hex/Octal/Decimal IP | ✅ | ❌ | ⚠️ |
| DNS rebinding protection | ✅ | ❌ | ❌ |
| Gopher / file block | ✅ | ❌ | ⚠️ |
| Cloud metadata | ✅ | ⚠️ | ❌ |
| Port blocking | ✅ | ❌ | ❌ |
| Bundle size | ~15 KB | ~2 KB | ~50 KB |
| Zero deps (core) | ✅* | ✅ | ❌ |
| Pro dashboard | ✅ | ❌ | ❌ |

*Core uses only `ipaddr.js` as a single lightweight dependency.

---

## Security Reporting

Found a bypass? We take security seriously.

- **Email**: security@ssrf-shield.io
- **Responsible disclosure**: We respond within 48 hours
- **Bug bounty**: Up to $500 for novel bypass techniques

---

## License

MIT — free for commercial use.

Pro features (dashboard, webhooks, allowlist) require a paid license at [ssrf-shield.io/pro](https://ssrf-shield.io/pro).

---

## Links

- 📖 [Documentation](https://ssrf-shield.io/docs)
- 🔑 [Pro License](https://ssrf-shield.io/pro)
- 🐛 [Issues](https://github.com/Brah-Timo/ssrf-shield/issues)
- 📦 [npm](https://www.npmjs.com/package/ssrf-shield)
- 🛡️ [OWASP SSRF](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)


