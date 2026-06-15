# Changelog

All notable changes to ssrf-shield are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2026-06-01

### Added
- Core SSRF protection engine (`checkUrl`, `checkUrlSync`)
- Express middleware (`ssrfGuard()`)
- Fastify hook adapter (`ssrfGuardFastify()`)
- URL normalization layer (backslash, null bytes, credentials, Unicode NFC)
- Scheme validation — 35+ dangerous protocols blocked (gopher, file, dict, ftp, data, ...)
- Port validation — 35+ internal service ports blocked (Redis, MongoDB, PostgreSQL, ...)
- IPv4 CIDR range checks (loopback, RFC1918, link-local, cloud metadata, CGN, multicast, broadcast)
- IPv6 CIDR range checks (loopback, link-local, unique local, IPv4-mapped, Teredo, ...)
- IP encoding bypass protection (hex, octal, decimal integer, short-form, leading zeros)
- IPv4-mapped IPv6 unwrapping (::ffff:127.0.0.1 → 127.0.0.1)
- DNS resolution with A + AAAA record checking
- DNS timeout with fail-safe blocking (default 3000ms)
- Cloud metadata endpoint blocklist (AWS, GCP, Azure, Alibaba, OCI, DigitalOcean, Kubernetes)
- Cloud metadata hostname blocking (metadata.google.internal, kubernetes.default.svc)
- Pro: Custom allowlist with exact hostname, wildcard subdomain, exact IP, CIDR support
- Pro: Block/allow event callbacks (`onBlock`, `onAllow`)
- Pro: Security event logger with batching and retry
- Pro: Webhook alerter with Slack/PagerDuty/Discord/generic formats and HMAC signing
- Pro: In-memory rate limiter with configurable window
- Full TypeScript typings with strict mode
- Comprehensive test suite: unit + integration + 80+ bypass attempt coverage

### Security
- All security layers are fail-safe (block on ambiguity, not allow)
- No dependency on insecure string comparison (uses Set for O(1) lookups)
- DNS timeout prevents slow-loris DNS attacks
- Credentials stripped from URLs before downstream use

---

## [Unreleased]

### Planned
- Redis-backed distributed rate limiter
- Express v5 compatibility
- Hono adapter
- SSRF honeypot mode (log + allow, for research environments)
- Allowlist wildcards via regex
- ipinfo.io integration for geographic blocking
- OpenTelemetry trace support


