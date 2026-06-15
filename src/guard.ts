/**
 * ssrf-shield Core Engine — guard.ts
 * ────────────────────────────────────
 * The central orchestrator. Runs every URL through all security layers
 * in the correct order and returns a structured GuardResult.
 *
 * Layer execution order:
 *  1. URL validation + normalization (syntax, scheme, hostname existence)
 *  2. Port validation (block internal service ports)
 *  3. Pro allowlist check (skip remaining checks for trusted hosts)
 *  4. Direct IP check (if hostname is an IP address)
 *  5. DNS resolution + check (if hostname is a domain name)
 *  6. DNS rebinding second-check (if enabled in options)
 *
 * Design principles:
 *  - Fail-safe: On ambiguity, BLOCK. Never allow unclear cases.
 *  - Defense in depth: Multiple independent layers; bypassing one is not enough.
 *  - Performance: DNS lookup only when needed; IP checks are synchronous O(n).
 *  - Transparency: Every block includes reason + threat category + duration.
 */

import { validateUrl } from './validators/url-validator.js';
import { checkIpAddress } from './validators/ip-validator.js';
import { validatePort } from './validators/protocol-validator.js';
import { resolveAndCheckDns } from './validators/dns-resolver.js';
import { checkAllowlist } from './pro/ip-whitelist.js';
import { makeBlockedResult, makeAllowedResult } from './types/result.js';
import type { GuardResult } from './types/result.js';
import type { SsrfGuardOptions } from './types/options.js';
import { resolveOptions } from './utils/options-resolver.js';

export type { GuardResult, BlockedResult, AllowedResult } from './types/result.js';

/**
 * The main ssrf-shield check function.
 *
 * Analyzes a URL and determines whether it's safe for the server to fetch.
 * This is the function behind both the Express middleware and standalone use.
 *
 * @param rawUrl  - The raw URL string provided by the user
 * @param options - Configuration options
 * @returns GuardResult — check allowed/blocked + details
 *
 * @example
 * ```typescript
 * const result = await checkUrl('http://169.254.169.254/latest/meta-data/', options);
 * if (!result.allowed) {
 *   console.log('BLOCKED:', result.threat?.reason);
 * }
 * ```
 */
export async function checkUrl(
  rawUrl: string,
  options: SsrfGuardOptions = {},
): Promise<GuardResult> {
  const startTime = Date.now();
  const resolved = resolveOptions(options);

  // ══════════════════════════════════════════════════════════════════════════
  // LAYER 1: URL Structural Validation
  // Validates format, scheme, hostname presence, cloud metadata hostnames.
  // ══════════════════════════════════════════════════════════════════════════
  const urlCheck = validateUrl(rawUrl);
  if (!urlCheck.valid) {
    return makeBlockedResult(
      urlCheck.threatCategory ?? 'INVALID_URL',
      urlCheck.reason ?? 'URL validation failed',
      startTime,
    );
  }

  // We now have a clean, normalized URL and parsed components
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  const normalizedUrl = urlCheck.normalizedUrl ?? '';
  const hostname = urlCheck.hostname ?? '';
  const effectivePort = urlCheck.port;

  // ══════════════════════════════════════════════════════════════════════════
  // LAYER 2: Port Validation
  // Blocks connections to internal service ports (Redis, MongoDB, etc.)
  // ══════════════════════════════════════════════════════════════════════════
  const portCheck = validatePort(effectivePort, resolved.effectiveBlockedPorts);
  if (!portCheck.valid) {
    return makeBlockedResult(
      portCheck.threatCategory ?? 'BLOCKED_PORT',
      portCheck.reason ?? `Port ${effectivePort} is blocked`,
      startTime,
    );
  }

  // ══════════════════════════════════════════════════════════════════════════
  // LAYER 3: Pro Allowlist Check
  // If the host is in the trusted allowlist, skip all further checks.
  // ══════════════════════════════════════════════════════════════════════════
  if (resolved.isPro && resolved.allowlistPatterns.length > 0) {
    const inAllowlist = checkAllowlist(hostname, resolved.allowlistPatterns);
    if (inAllowlist) {
      return makeAllowedResult(normalizedUrl, startTime);
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // LAYER 4: Direct IP Check
  // If hostname is an IP address (not a domain), check it directly.
  // Handles all encoding tricks via ip-parser and ip-validator.
  // ══════════════════════════════════════════════════════════════════════════
  if (urlCheck.isDirectIpAddress) {
    const ipCheck = checkIpAddress(hostname);
    if (ipCheck.blocked) {
      return makeBlockedResult(
        ipCheck.threatCategory ?? 'PRIVATE_IP',
        ipCheck.reason ?? `IP address ${ipCheck.canonicalIp} is blocked`,
        startTime,
        {
          blockedValue: ipCheck.canonicalIp,
          matchedRange: ipCheck.matchedRange,
          likelyBypassAttempt: ipCheck.wasEncoded,
        },
      );
    }
    // Direct IP passed all checks
    return makeAllowedResult(normalizedUrl, startTime, [ipCheck.canonicalIp]);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // LAYER 5: DNS Resolution + IP Check
  // Resolve the hostname to IP addresses and check each one.
  // If ANY resolved IP is in a blocked range, block the request.
  // ══════════════════════════════════════════════════════════════════════════
  if (resolved.skipDnsResolution) {
    // User opted to skip DNS — only static URL/IP checks were applied
    return makeAllowedResult(normalizedUrl, startTime);
  }

  let resolvedIps: string[] = [];
  try {
    const dnsResult = await resolveAndCheckDns(hostname, resolved.dnsTimeoutMs);

    if (!dnsResult.safe) {
      return makeBlockedResult(
        dnsResult.threatCategory ?? 'DNS_RESOLVED_PRIVATE',
        dnsResult.reason ?? `Hostname "${hostname}" resolved to a blocked IP`,
        startTime,
        {
          blockedValue: dnsResult.blockedIp,
          resolvedIps: dnsResult.resolvedIps,
        },
      );
    }

    resolvedIps = dnsResult.resolvedIps;

    // If DNS returned no IPs at all (NXDOMAIN, etc.)
    if (dnsResult.skipped === true && resolvedIps.length === 0) {
      if (!resolved.allowOnDnsError) {
        return makeBlockedResult(
          'DNS_ERROR',
          `Could not resolve hostname: "${hostname}"`,
          startTime,
        );
      }
      // allowOnDnsError = true → let it through
      return makeAllowedResult(normalizedUrl, startTime, []);
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);

    if (message.includes('timed out') || message.includes('DNS_TIMEOUT')) {
      return makeBlockedResult(
        'DNS_TIMEOUT',
        `DNS resolution timed out for hostname: "${hostname}"`,
        startTime,
      );
    }

    if (!resolved.allowOnDnsError) {
      return makeBlockedResult(
        'DNS_ERROR',
        `DNS resolution failed for hostname: "${hostname}". Reason: ${message}`,
        startTime,
      );
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // ALL CHECKS PASSED — Request is safe
  // Return the sanitized URL so downstream handlers always use the clean form
  // ══════════════════════════════════════════════════════════════════════════
  return makeAllowedResult(normalizedUrl, startTime, resolvedIps);
}

/**
 * Synchronous version of checkUrl for direct-IP-only scenarios.
 * Does NOT perform DNS resolution — use only when you control all URLs
 * and they are guaranteed to be IP addresses.
 *
 * WARNING: Skipping DNS resolution leaves you vulnerable to DNS rebinding.
 *
 * @param rawUrl  - URL with a direct IP address hostname
 * @param options - Configuration options (dnsTimeoutMs and DNS options ignored)
 */
export function checkUrlSync(
  rawUrl: string,
  options: SsrfGuardOptions = {},
): GuardResult {
  const startTime = Date.now();
  const resolved = resolveOptions({ ...options, skipDnsResolution: true });

  const urlCheck = validateUrl(rawUrl);
  if (!urlCheck.valid) {
    return makeBlockedResult(
      urlCheck.threatCategory ?? 'INVALID_URL',
      urlCheck.reason ?? 'URL validation failed',
      startTime,
    );
  }

  const normalizedUrl = urlCheck.normalizedUrl ?? '';
  const hostname = urlCheck.hostname ?? '';
  const effectivePort = urlCheck.port;

  const portCheck = validatePort(effectivePort, resolved.effectiveBlockedPorts);
  if (!portCheck.valid) {
    return makeBlockedResult(
      portCheck.threatCategory ?? 'BLOCKED_PORT',
      portCheck.reason ?? `Port ${effectivePort} is blocked`,
      startTime,
    );
  }

  if (!urlCheck.isDirectIpAddress) {
    // Hostname — can't check without DNS, allow (caller chose sync mode)
    return makeAllowedResult(normalizedUrl, startTime);
  }

  const ipCheck = checkIpAddress(hostname);
  if (ipCheck.blocked) {
    return makeBlockedResult(
      ipCheck.threatCategory ?? 'PRIVATE_IP',
      ipCheck.reason ?? `IP ${ipCheck.canonicalIp} is blocked`,
      startTime,
      { blockedValue: ipCheck.canonicalIp, matchedRange: ipCheck.matchedRange },
    );
  }

  return makeAllowedResult(normalizedUrl, startTime, [ipCheck.canonicalIp]);
}

/**
 * Re-export resolveOptions for users who need the resolved config.
 */
export { resolveOptions } from './utils/options-resolver.js';
export type { ResolvedOptions } from './types/options.js';

