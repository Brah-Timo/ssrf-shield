/**
 * DNS Resolver with Anti-Rebinding Protection
 * ─────────────────────────────────────────────
 * The most sophisticated layer of ssrf-shield.
 *
 * Problem: An attacker can register a domain like `evil.attacker.com`
 * that normally resolves to a public IP (passes your check), but
 * then quickly changes the DNS record to 127.0.0.1 before your code
 * makes the actual HTTP request. This is "DNS Rebinding."
 *
 * Solution:
 *  1. Resolve the hostname to ALL its IP addresses (A + AAAA records)
 *  2. Check every resolved IP against the blocked ranges
 *  3. Reject if ANY resolved IP is in a blocked range
 *  4. Optionally: double-check DNS right before making the request
 *     (doubleCheckDns) to catch time-of-check/time-of-use gaps
 *
 * Additional protections:
 *  - Timeout: DNS resolution has a configurable timeout (default: 3s)
 *    On timeout → block request (fail-safe)
 *  - IPv4 + IPv6: Both A and AAAA records are checked
 *    (bypass attempt: give public IPv4 but private IPv6)
 *  - IPv4-mapped: ::ffff:127.0.0.1 is treated as 127.0.0.1
 */

import dns from 'dns/promises';
import { checkIpAddress } from './ip-validator.js';
import type { ThreatCategory } from '../types/threat.js';

export interface DnsCheckResult {
  /** Whether DNS resolution passed all security checks */
  safe: boolean;
  /** All resolved IP addresses (both IPv4 and IPv6) */
  resolvedIps: string[];
  /** The specific IP that triggered a block (if any) */
  blockedIp?: string;
  /** Human-readable reason (if blocked) */
  reason?: string;
  /** Threat category (if blocked) */
  threatCategory?: ThreatCategory;
  /** Whether DNS resolution was skipped (e.g., already a direct IP) */
  skipped?: boolean;
}

export interface DnsRebindingCheckResult {
  /** true = DNS is stable (same IPs), false = DNS changed (possible rebinding) */
  stable: boolean;
  /** IPs from the second resolution */
  currentIps: string[];
  /** New IPs that appeared since the first resolution */
  newIps: string[];
}

/**
 * Resolve a hostname via DNS and check all resulting IPs against blocked ranges.
 *
 * @param hostname    - The hostname to resolve (not an IP address)
 * @param timeoutMs   - Maximum time to wait for DNS resolution (default: 3000ms)
 * @returns DnsCheckResult
 */
export async function resolveAndCheckDns(
  hostname: string,
  timeoutMs = 3000,
): Promise<DnsCheckResult> {
  const resolvedIps: string[] = [];

  // ── Resolve IPv4 (A records) ───────────────────────────────────────────────
  try {
    const v4Addresses = await withTimeout(
      dns.resolve4(hostname),
      timeoutMs,
      `DNS resolution timed out for: ${hostname}`,
    );
    resolvedIps.push(...v4Addresses);
  } catch (err: unknown) {
    if (isTimeoutError(err)) {
      return {
        safe: false,
        resolvedIps: [],
        reason: `DNS resolution timed out for hostname: ${hostname}`,
        threatCategory: 'DNS_TIMEOUT',
      };
    }
    // ENOTFOUND, ENODATA, etc. — domain doesn't exist or has no A records
    // This is handled by the caller (allowOnDnsError option)
  }

  // ── Resolve IPv6 (AAAA records) ────────────────────────────────────────────
  // Critical: attackers can register a domain with a safe IPv4 address
  // but point its IPv6 to ::1 (loopback)
  try {
    const v6Addresses = await withTimeout(
      dns.resolve6(hostname),
      timeoutMs,
      `DNS resolution timed out for: ${hostname}`,
    );
    resolvedIps.push(...v6Addresses);
  } catch (err: unknown) {
    if (isTimeoutError(err)) {
      return {
        safe: false,
        resolvedIps,
        reason: `DNS (AAAA) resolution timed out for hostname: ${hostname}`,
        threatCategory: 'DNS_TIMEOUT',
      };
    }
    // ENODATA = no AAAA records — perfectly normal, continue
  }

  // ── No IPs resolved — domain doesn't exist ────────────────────────────────
  if (resolvedIps.length === 0) {
    // Caller decides: allowOnDnsError determines whether to allow or block
    return {
      safe: true, // We can't verify but also can't block — let caller decide
      resolvedIps: [],
      skipped: true,
    };
  }

  // ── Check every resolved IP ───────────────────────────────────────────────
  // ONE bad IP out of many is enough to block the entire request.
  // Attackers may use round-robin DNS with a mix of safe + unsafe IPs,
  // hoping the request will eventually hit the unsafe one.
  for (const ip of resolvedIps) {
    const check = checkIpAddress(ip);
    if (check.blocked) {
      return {
        safe: false,
        resolvedIps,
        blockedIp: check.canonicalIp,
        reason:
          check.reason ??
          `DNS resolved to blocked IP ${check.canonicalIp} for hostname ${hostname}`,
        threatCategory: check.threatCategory ?? 'DNS_RESOLVED_PRIVATE',
      };
    }
  }

  return { safe: true, resolvedIps };
}

/**
 * DNS Rebinding Protection — Double-check DNS.
 *
 * Call this a second time right before making the actual HTTP request
 * (after following any redirects). If the DNS has changed and the new
 * IPs include private addresses, it's a DNS rebinding attack.
 *
 * Typical usage:
 *   1. resolveAndCheckDns(hostname) → save resolvedIps
 *   2. ... (time passes, redirects happen) ...
 *   3. doubleCheckDns(hostname, resolvedIps) → if !stable → block
 *
 * @param hostname    - Original hostname to re-resolve
 * @param previousIps - IPs from the first DNS resolution
 * @param timeoutMs   - DNS timeout
 */
export async function doubleCheckDns(
  hostname: string,
  previousIps: readonly string[],
  timeoutMs = 3000,
): Promise<DnsRebindingCheckResult> {
  const secondResult = await resolveAndCheckDns(hostname, timeoutMs);
  const currentIps = secondResult.resolvedIps;
  const previousSet = new Set(previousIps);

  // Find IPs that appeared in the second resolution but not the first
  const newIps = currentIps.filter((ip) => !previousSet.has(ip));

  // If DNS is stable (same IPs), no rebinding
  if (newIps.length === 0) {
    return { stable: true, currentIps, newIps: [] };
  }

  // New IPs appeared — check if any are blocked
  const hasNewBlockedIps = newIps.some((ip) => checkIpAddress(ip).blocked);

  return {
    stable: !hasNewBlockedIps,
    currentIps,
    newIps,
  };
}

/**
 * Wrap a promise with a timeout.
 * Rejects with a timeout error if the promise doesn't resolve in time.
 */
function withTimeout<T>(
  promise: Promise<T>,
  ms: number,
  message: string,
): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      const timer = setTimeout(() => {
        reject(new DnsTimeoutError(message));
      }, ms);
      // Allow Node.js to exit even if timer is pending
      if (typeof timer === 'object' && 'unref' in timer) {
        timer.unref();
      }
    }),
  ]);
}

class DnsTimeoutError extends Error {
  public readonly code = 'DNS_TIMEOUT' as const;
  public constructor(message: string) {
    super(message);
    this.name = 'DnsTimeoutError';
  }
}

function isTimeoutError(err: unknown): boolean {
  return (
    err instanceof DnsTimeoutError ||
    (err instanceof Error && err.message.includes('timed out'))
  );
}

