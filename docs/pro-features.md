# Pro Features

Get a Pro license at **https://ssrf-shield.io/pro** — $29/month.

## Setup

```typescript
import { ssrfGuard } from 'ssrf-shield';

app.use(ssrfGuard({
  proLicense: process.env.SSRF_GUARD_KEY,  // required for Pro features
  // ... pro options below
}));
```

Set your key in environment:
```bash
export SSRF_GUARD_KEY=sgpro_your_key_here
```

---

## Feature 1: Custom Allowlist

Bypass SSRF checks for trusted internal services.

```typescript
ssrfGuard({
  proLicense: process.env.SSRF_GUARD_KEY,
  allowlist: [
    'api.myservice.com',          // exact hostname
    '*.internal.mycompany.corp',   // wildcard subdomain
    '10.0.1.5',                    // exact IP
    '10.0.1.0/24',                 // CIDR range
  ],
})
```

---

## Feature 2: Block Event Callbacks

React to every SSRF attack attempt in real time.

```typescript
import { ssrfGuard, SsrfGuardLogger } from 'ssrf-shield';

const logger = new SsrfGuardLogger({
  licenseKey: process.env.SSRF_GUARD_KEY!,
  consoleLog: true,  // also log to console
});

ssrfGuard({
  proLicense: process.env.SSRF_GUARD_KEY,
  onBlock: async (event) => {
    // event.threatCategory  ← 'LOOPBACK', 'CLOUD_METADATA', etc.
    // event.severity        ← 'critical', 'high', 'medium', 'low'
    // event.likelyBypassAttempt ← true if it looks intentional
    // event.ip, event.url, event.requestPath, event.userAgent
    
    logger.logBlock(event);
    
    if (event.severity === 'critical') {
      await pagerDuty.trigger(`SSRF from ${event.ip}: ${event.url}`);
    }
  },
  onAllow: (event) => {
    metrics.increment('ssrf.allowed');
  },
})
```

---

## Feature 3: Webhook Alerts

Real-time notifications to Slack, PagerDuty, Discord, or any HTTP endpoint.

```typescript
import { WebhookAlerter } from 'ssrf-shield';

const alerter = new WebhookAlerter({
  url: process.env.SLACK_WEBHOOK_URL!,
  secret: process.env.WEBHOOK_SECRET,
  minSeverity: 'high',      // only alert on high/critical
  format: 'slack',          // 'ssrf-shield' | 'slack' | 'pagerduty' | 'discord'
});

ssrfGuard({
  proLicense: process.env.SSRF_GUARD_KEY,
  onBlock: (event) => alerter.send(event),
})
```

Supported formats:
- `ssrf-shield` — structured JSON with full event data
- `slack` — rich block message with severity colors
- `pagerduty` — Events API v2 compatible
- `discord` — embed with color-coded severity

---

## Feature 4: Rate Limiting

Prevent attackers from enumerating your internal network.

```typescript
import { SsrfRateLimiter, extractClientIp } from 'ssrf-shield';

const limiter = new SsrfRateLimiter({
  maxRequests: 50,    // 50 requests
  windowSecs: 60,     // per minute per IP
});

app.use((req, res, next) => {
  const ip = extractClientIp(req, 1);  // trust 1 proxy hop
  const result = limiter.check(ip);
  
  if (!result.allowed) {
    return res.status(429).json({
      error: 'RATE_LIMITED',
      retryAfter: result.resetAt,
    });
  }
  
  // Set rate limit headers
  res.set('X-RateLimit-Limit', String(result.limit));
  res.set('X-RateLimit-Remaining', String(result.remaining));
  res.set('X-RateLimit-Reset', String(result.resetAt));
  next();
});
```

---

## Feature 5: Security Event Logger

Ships events to the ssrf-shield Pro dashboard for visualization.

```typescript
import { SsrfGuardLogger } from 'ssrf-shield';

const logger = new SsrfGuardLogger({
  licenseKey: process.env.SSRF_GUARD_KEY!,
  flushIntervalMs: 5000,  // batch every 5 seconds
  maxBufferSize: 50,       // or flush after 50 events
  consoleLog: false,       // disable console output in production
});

// Graceful shutdown
process.on('SIGTERM', async () => {
  await logger.shutdown();  // flushes remaining events
  process.exit(0);
});
```

**Dashboard features:**
- Real-time attack map (geographic distribution)
- Threat category breakdown
- Top attacking IPs
- Timeline and trends
- Bypass attempt detection rate
- Export to CSV/JSON

---

## Complete Pro Setup Example

```typescript
import express from 'express';
import { ssrfGuard, SsrfGuardLogger, WebhookAlerter, SsrfRateLimiter, extractClientIp } from 'ssrf-shield';

const app = express();

const logger = new SsrfGuardLogger({ licenseKey: process.env.SSRF_GUARD_KEY! });
const alerter = new WebhookAlerter({ url: process.env.SLACK_WEBHOOK!, format: 'slack', minSeverity: 'high' });
const limiter = new SsrfRateLimiter({ maxRequests: 100, windowSecs: 60 });

// Global rate limiting
app.use((req, res, next) => {
  const ip = extractClientIp(req, 1);
  const rl = limiter.check(ip);
  if (!rl.allowed) return res.status(429).json({ error: 'RATE_LIMITED' });
  next();
});

// SSRF guard with all Pro features
app.use(ssrfGuard({
  proLicense: process.env.SSRF_GUARD_KEY,
  allowlist: ['*.internal.mycompany.com', '10.0.0.0/8'],
  onBlock: async (event) => {
    logger.logBlock(event);
    if (event.severity === 'critical') alerter.send(event);
  },
  onAllow: (event) => logger.logAllow(event),
}));

process.on('SIGTERM', async () => {
  await logger.shutdown();
  process.exit(0);
});
```


