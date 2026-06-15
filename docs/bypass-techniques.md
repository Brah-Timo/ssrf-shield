# SSRF Bypass Techniques & Defenses

A comprehensive breakdown of every known bypass technique and exactly how ssrf-shield defends against each one.

---

## 1. Localhost Encoding Tricks

### Technique
Attackers represent `127.0.0.1` in unusual formats that bypass naive string-matching:

```
http://2130706433/          ← decimal integer
http://0x7f000001/          ← hexadecimal
http://0177.0.0.1/          ← octal first octet
http://127.1/               ← short-form IPv4
http://127.000.000.001/     ← leading zeros
```

### Defense
`url-normalizer.ts` + `ip-parser.ts` convert ALL formats to canonical dotted-decimal before checking. The `ipaddr.js` library also normalizes unusual forms. Then `ip-validator.ts` checks the canonical form against `127.0.0.0/8`.

---

## 2. IPv6 Representation

### Technique
Use IPv6 representations of private addresses:

```
http://[::1]/                       ← IPv6 loopback
http://[::ffff:127.0.0.1]/          ← IPv4-mapped IPv6
http://[::ffff:7f00:1]/             ← IPv4-mapped hex
http://[0:0:0:0:0:ffff:127.0.0.1]/ ← full form
http://[fe80::1]/                   ← link-local
http://[fc00::1]/                   ← unique local (≈ RFC1918)
```

### Defense
- `ipaddr.js` detects IPv4-mapped IPv6 and converts to plain IPv4 before range checks
- `BLOCKED_IPV6_RANGES` covers all IPv6 private/loopback ranges explicitly
- Both A (IPv4) and AAAA (IPv6) records are checked during DNS resolution

---

## 3. URL Credentials Bypass

### Technique
The URL standard allows `user@host` syntax. Naive parsers use the wrong part as the host:

```
http://attacker.com@127.0.0.1/   ← real host: 127.0.0.1
http://legit.com@192.168.1.1/    ← real host: 192.168.1.1
```

### Defense
`url-normalizer.ts` uses the WHATWG URL API (Node.js `new URL()`), which correctly identifies `parsed.hostname` as `127.0.0.1`, not `attacker.com`. Credentials are then stripped from the normalized URL.

---

## 4. Alternative Schemes (Gopher, file, dict)

### Technique
HTTP is not the only protocol. Attackers use:

```
gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
  → Sends raw FLUSHALL command to Redis
  
file:///etc/passwd
  → Reads local files
  
dict://localhost:11211/stats
  → Queries Memcached
```

### Defense
`dangerous-schemes.ts` maintains a Set of 35+ blocked protocols. Only `http` and `https` are allowed. Checked BEFORE any DNS lookup.

---

## 5. DNS Rebinding

### Technique
1. Register a domain with a valid public TTL and short TTL (e.g., 1 second)
2. Initially resolves to a legitimate public IP → passes your SSRF check
3. Before the actual HTTP request is made, update DNS to resolve to `127.0.0.1`
4. The server fetches from localhost

### Defense
- `resolveAndCheckDns()` resolves ALL IP addresses (A + AAAA) and blocks if ANY is private
- `doubleCheckDns()` can be called a second time right before the fetch to re-verify
- Short DNS timeout (3s default) limits the attack window
- Future: `enableDnsRebindingProtection` option forces double-check automatically

---

## 6. Round-Robin DNS Poisoning

### Technique
Register a domain with multiple A records — some public, some private — hoping the server picks the private one:

```
evil.attacker.com → 8.8.8.8, 127.0.0.1
```

### Defense
`resolveAndCheckDns()` checks **every** resolved IP address. If ANY IP in the response is in a blocked range, the entire request is rejected.

---

## 7. Cloud Metadata via Hostname

### Technique
GCP exposes metadata via a hostname, not just IP:

```
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
```

### Defense
`cloud-metadata.ts` maintains an explicit set of metadata hostnames. `url-validator.ts` checks against this list before even attempting DNS resolution.

---

## 8. Port-based Attacks

### Technique
Even with a public IP, attack internal services by targeting specific ports:

```
http://example.com:6379/     ← Redis
http://example.com:9200/     ← Elasticsearch
http://example.com:2375/     ← Docker API (unauthenticated)
```

### Defense
`protocol-validator.ts` maintains a list of 35+ blocked service ports. Checked before DNS resolution.

---

## 9. URL Fragment / Null Byte Injection

### Technique
```
http://localhost%00.evil.com/   ← some parsers stop at null byte
http://localhost#@evil.com/     ← fragment confusion
```

### Defense
`url-normalizer.ts` removes all control characters (including `\x00`) before parsing, then uses the WHATWG URL API which handles fragments correctly.

---

## 10. Protocol-Relative and Backslash URLs

### Technique
```
//localhost/                 ← protocol-relative (treated as http:)
http:\\localhost\path        ← backslash confusion
http:///localhost/           ← triple-slash
```

### Defense
`url-normalizer.ts` replaces all backslashes with forward slashes, then normalizes `http:///` to `http://` before calling `new URL()`.

---

## Defense-in-Depth Summary

```
┌─────────────────────────────────────────────────┐
│  LAYER 1: URL Normalization                      │
│  • Strips backslashes, null bytes, whitespace    │
│  • Removes embedded credentials                  │
│  • Unicode NFC normalization                     │
│  • WHATWG URL API parsing (browser-accurate)     │
├─────────────────────────────────────────────────┤
│  LAYER 2: Scheme Validation                      │
│  • 35+ blocked protocols (gopher, file, dict...) │
│  • Only http and https allowed                   │
├─────────────────────────────────────────────────┤
│  LAYER 3: Port Validation                        │
│  • 35+ blocked service ports (Redis, MongoDB...) │
├─────────────────────────────────────────────────┤
│  LAYER 4: IP Validation (direct IPs)             │
│  • ipaddr.js normalizes hex/octal/decimal        │
│  • IPv4-mapped IPv6 unwrapping                   │
│  • Full CIDR range matching (IPv4 + IPv6)        │
│  • Cloud metadata IP explicit blocklist          │
├─────────────────────────────────────────────────┤
│  LAYER 5: DNS Resolution                         │
│  • A + AAAA record resolution                    │
│  • ALL IPs checked (no round-robin escape)       │
│  • 3-second timeout (fail-safe)                  │
│  • Cloud metadata hostname check                 │
└─────────────────────────────────────────────────┘
```


