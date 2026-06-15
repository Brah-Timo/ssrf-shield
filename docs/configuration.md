# Configuration Reference

## `SsrfGuardOptions`

All options are optional. Sensible, secure defaults are applied.

### Core Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `urlParam` | `string` | `'url'` | Name of the request parameter containing the URL to validate |
| `blockedPorts` | `number[]` | built-in list | Override the entire blocked ports list |
| `additionalBlockedPorts` | `number[]` | `[]` | Add ports to the built-in blocked list |
| `dnsTimeoutMs` | `number` | `3000` | DNS resolution timeout (ms). On timeout → block (fail-safe) |
| `allowOnDnsError` | `boolean` | `false` | Allow requests when DNS fails (fail-open vs fail-safe) |
| `exposeReason` | `boolean` | `false` | Include block reason in HTTP response (⚠️ reveals info) |
| `blockedStatusCode` | `number` | `403` | HTTP status code for blocked requests |
| `skipDnsResolution` | `boolean` | `false` | Skip DNS check entirely (only for direct-IP URLs) |
| `enableDnsRebindingProtection` | `boolean` | `false` | Double-check DNS after redirects |

### Pro Options (requires `proLicense`)

| Option | Type | Description |
|--------|------|-------------|
| `proLicense` | `string` | Your ssrf-shield Pro key |
| `allowlist` | `string[]` | Trusted hosts that bypass all SSRF checks |
| `onBlock` | `function` | Callback fired on every blocked request |
| `onAllow` | `function` | Callback fired on every allowed request |
| `rateLimit` | `RateLimitOptions` | Per-IP rate limiting |
| `webhookUrl` | `string` | Webhook endpoint for real-time alerts |
| `webhookSecret` | `string` | HMAC secret for webhook signature |

---

## Built-in Blocked Ports

The following ports are blocked by default:

```
22    SSH
23    Telnet
25    SMTP
53    DNS (TCP)
110   POP3
143   IMAP
389   LDAP
445   SMB
636   LDAPS
1433  SQL Server
1521  Oracle DB
2049  NFS
2181  ZooKeeper
2375  Docker API (unauthenticated!)
2376  Docker API (TLS)
2379  etcd
2380  etcd peer
3306  MySQL / MariaDB
3389  RDP
4001  etcd legacy
5432  PostgreSQL
5672  RabbitMQ AMQP
5900  VNC
5984  CouchDB
6379  Redis ← most common target
6380  Redis TLS
7001  WebLogic
8086  InfluxDB
8500  Consul
8888  Jupyter Notebook
9042  Cassandra
9090  Prometheus
9092  Kafka
9200  Elasticsearch HTTP
9300  Elasticsearch transport
10250 Kubernetes Kubelet API
11211 Memcached
15672 RabbitMQ Management UI
27017 MongoDB
27018 MongoDB shard
27019 MongoDB config
50070 Hadoop NameNode
61616 ActiveMQ
```

To add extra ports without replacing the list:
```typescript
ssrfGuard({ additionalBlockedPorts: [8080, 9999] })
```

To completely override the list:
```typescript
ssrfGuard({ blockedPorts: [6379, 27017] }) // only these two
```

---

## URL Parameter Extraction

The middleware checks these locations in order:
1. `req.query[urlParam]`
2. `req.body[urlParam]`
3. `req.params[urlParam]`

```typescript
// Custom param name
app.post('/proxy', ssrfGuard({ urlParam: 'target' }), handler);
// Now reads: req.body.target or req.query.target
```

---

## Accessing the Safe URL

After the middleware passes, use `req.ssrfGuard.safeUrl` for downstream requests:

```typescript
app.get('/fetch', ssrfGuard(), async (req, res) => {
  // ✅ Always use the safe, normalized URL — never req.query.url directly
  const data = await fetch(req.ssrfGuard!.safeUrl);
  res.json(await data.json());
});
```

---

## Allowlist Configuration (Pro)

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

**Security note**: The allowlist bypasses ALL checks. Only add hosts you fully control.

---

## DNS Timeout Tuning

```typescript
// Faster (risker — may block legitimate slow resolvers)
ssrfGuard({ dnsTimeoutMs: 1000 })

// More lenient (default: 3000ms)
ssrfGuard({ dnsTimeoutMs: 5000 })

// Fail-open on DNS error (NOT recommended for high-security apps)
ssrfGuard({ allowOnDnsError: true })
```


