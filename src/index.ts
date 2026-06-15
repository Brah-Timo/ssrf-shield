/**
 * ssrf-shield — Main Package Entry Point
 * ───────────────────────────────────────
 * Block SSRF attacks in one line. Production-ready middleware for
 * Express, Fastify, Hono, Koa, and any Node.js application.
 *
 * Quick Start:
 * ─────────────────────────────────────────────────────────────────────────────
 *   import { ssrfGuard } from 'ssrf-shield';
 *
 *   app.get('/fetch', ssrfGuard(), async (req, res) => {
 *     const data = await fetch(req.ssrfGuard!.safeUrl);
 *     res.json(await data.json());
 *   });
 *
 * Standalone (no framework):
 * ─────────────────────────────────────────────────────────────────────────────
 *   import { checkUrl } from 'ssrf-shield';
 *
 *   const result = await checkUrl(userProvidedUrl);
 *   if (!result.allowed) {
 *     throw new Error('Blocked: ' + result.threat?.reason);
 *   }
 *   const response = await fetch(result.safeUrl);
 *
 * Documentation: https://ssrf-shield.io/docs
 * Pro features:  https://ssrf-shield.io/pro
 */

// ─── Primary API ─────────────────────────────────────────────────────────────

/**
 * Express middleware — the recommended way to use ssrf-shield.
 * Automatically extracts the URL from the request and blocks SSRF attempts.
 */
export { ssrfGuard } from './middleware.js';

/**
 * Fastify hook adapter.
 */
export { ssrfGuardFastify } from './middleware.js';

/**
 * Core check function — framework-agnostic.
 * Use this when you're not using Express/Fastify, or when you need
 * programmatic control (e.g., validate before storing in DB).
 */
export { checkUrl, checkUrlSync } from './guard.js';

// ─── Types — Public API ───────────────────────────────────────────────────────

export type { SsrfGuardOptions, BlockEvent, AllowEvent, RateLimitOptions } from './types/options.js';
export type { GuardResult, BlockedResult, AllowedResult } from './types/result.js';
export type { ThreatCategory, ThreatInfo } from './types/threat.js';

// ─── Advanced / Low-Level API ─────────────────────────────────────────────────
// These are exported for users who need fine-grained control or
// want to extend ssrf-shield with custom logic.

/**
 * Low-level IP address checker.
 * Validates a single IP against all blocked ranges.
 * Handles hex, octal, decimal, and IPv6-mapped encodings.
 */
export { checkIpAddress, isBlockedIp } from './validators/ip-validator.js';

/**
 * DNS resolver with anti-rebinding protection.
 * Resolves a hostname and checks all resulting IPs.
 */
export { resolveAndCheckDns, doubleCheckDns } from './validators/dns-resolver.js';

/**
 * URL normalizer — canonicalizes URLs before checking.
 * Strips credentials, removes encoding tricks, normalizes Unicode.
 */
export { normalizeUrl, parseNormalizedUrl, isDirectIp } from './utils/url-normalizer.js';

/**
 * IP address parser — handles all exotic encoding formats.
 * Converts hex/octal/decimal/short-form IPs to canonical dotted-decimal.
 */
export { parseIpAddress } from './utils/ip-parser.js';

/**
 * CIDR range utilities.
 */
export { isInCIDR, isIPv4InCIDR, isIPv6InCIDR, ipv4ToInt } from './utils/cidr.js';

/**
 * Scheme/protocol validator.
 */
export { validateScheme, isDangerousScheme, DANGEROUS_SCHEMES, ALLOWED_SCHEMES } from './blocklists/dangerous-schemes.js';

/**
 * Cloud metadata helpers.
 */
export { isCloudMetadataHost, getCloudMetadataEndpoint, CLOUD_METADATA_ENDPOINTS } from './blocklists/cloud-metadata.js';

/**
 * Blocked IP range lists (for reference/extension).
 */
export { BLOCKED_IPV4_RANGES, BLOCKED_IPV6_RANGES } from './blocklists/private-ranges.js';

/**
 * Default blocked ports list.
 */
export { DEFAULT_BLOCKED_PORTS } from './types/options.js';

// ─── Pro API ──────────────────────────────────────────────────────────────────

/**
 * [PRO] Allowlist checker.
 */
export { checkAllowlist } from './pro/ip-whitelist.js';

/**
 * [PRO] Structured logger for security events.
 */
export { SsrfGuardLogger } from './pro/logger.js';

/**
 * [PRO] Rate limiter.
 */
export { SsrfRateLimiter } from './pro/rate-limiter.js';

/**
 * [PRO] Webhook alerting.
 */
export { WebhookAlerter } from './pro/webhook-alerts.js';

// ─── Error classes ────────────────────────────────────────────────────────────

export { InvalidUrlError } from './utils/url-normalizer.js';
export { BlockedSchemeError } from './blocklists/dangerous-schemes.js';

// ─── Utility type guards ──────────────────────────────────────────────────────

export { isBlocked, isAllowed } from './types/result.js';
export { getThreatSeverity, isLikelyBypassAttempt } from './types/threat.js';

// ─── Package version ──────────────────────────────────────────────────────────

export const VERSION = '1.0.0';

