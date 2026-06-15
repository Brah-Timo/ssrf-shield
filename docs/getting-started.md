# Getting Started with ssrf-shield

## What is SSRF?

**Server-Side Request Forgery (SSRF)** is a web security vulnerability that allows attackers to induce the server-side application to make HTTP requests to an arbitrary domain or IP of the attacker's choosing.

When your application accepts a URL from user input and fetches it server-side, an attacker can send:
- `http://localhost:6379` — your Redis server
- `http://169.254.169.254/latest/meta-data/iam/` — AWS IAM credentials
- `http://192.168.1.1/admin` — your internal network

SSRF reached **#10 in OWASP Top 10 (2021)** and was behind the 2019 **Capital One breach** (106M records stolen via AWS IMDS).

---

## Installation

```bash
npm install ssrf-shield
```

**Requirements**: Node.js ≥ 18.0.0

---

## Quick Start

### Option 1: Express Middleware (Recommended)

```typescript
import express from 'express';
import { ssrfGuard } from 'ssrf-shield';

const app = express();

// Protect a single route
app.get('/fetch', ssrfGuard(), async (req, res) => {
  // req.ssrfGuard.safeUrl is the normalized, safe URL
  const response = await fetch(req.ssrfGuard!.safeUrl);
  res.json(await response.json());
});

app.listen(3000);
```

### Option 2: Standalone Function (Framework-agnostic)

```typescript
import { checkUrl } from 'ssrf-shield';

async function proxyHandler(userUrl: string) {
  const result = await checkUrl(userUrl);
  
  if (!result.allowed) {
    throw new Error(`SSRF blocked: ${result.threat?.reason}`);
  }
  
  // Always use result.safeUrl — it's normalized and verified
  return fetch(result.safeUrl!);
}
```

### Option 3: With Fastify

```typescript
import Fastify from 'fastify';
import { ssrfGuardFastify } from 'ssrf-shield';

const fastify = Fastify();

fastify.addHook('preHandler', ssrfGuardFastify({ urlParam: 'url' }));

fastify.get('/fetch', async (request, reply) => {
  const url = (request.query as { url: string }).url;
  const data = await fetch(url);
  return data.json();
});
```

---

## What Gets Blocked

| Attack Type | Example | Blocked |
|-------------|---------|---------|
| Localhost | `http://localhost:6379` | ✅ |
| Loopback | `http://127.0.0.1` | ✅ |
| AWS IMDS | `http://169.254.169.254/latest/meta-data/iam/` | ✅ |
| GCP IMDS | `http://metadata.google.internal/` | ✅ |
| Private network | `http://192.168.1.1/admin` | ✅ |
| IPv6 loopback | `http://[::1]/` | ✅ |
| IPv4-mapped IPv6 | `http://[::ffff:127.0.0.1]/` | ✅ |
| Hex IP | `http://0x7f000001/` | ✅ |
| Octal IP | `http://0177.0.0.1/` | ✅ |
| Decimal IP | `http://2130706433/` | ✅ |
| Gopher/Redis | `gopher://localhost:6379/_FLUSHALL` | ✅ |
| File read | `file:///etc/passwd` | ✅ |
| Internal ports | `http://example.com:6379/` | ✅ |
| DNS rebinding | `evil.com → 127.0.0.1` | ✅ |
| Public API | `https://api.github.com/` | ✅ allowed |

---

## Next Steps

- [Configuration Options](./configuration.md) — all available options
- [Pro Features](./pro-features.md) — allowlists, logging, webhooks
- [Bypass Techniques](./bypass-techniques.md) — how we defend against them


