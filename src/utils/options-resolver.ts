/**
 * Options Resolver
 * ─────────────────
 * Converts user-supplied SsrfGuardOptions into the internal ResolvedOptions
 * with all defaults applied and values validated.
 */

import { buildBlockedPortsSet } from '../validators/protocol-validator.js';
import type {
  SsrfGuardOptions,
  ResolvedOptions,
  AllowlistPattern,
} from '../types/options.js';

/**
 * Parse and resolve a single allowlist entry into a typed AllowlistPattern.
 *
 * Supported formats:
 *  - Exact hostname:      "api.example.com"
 *  - Wildcard subdomain:  "*.example.com"
 *  - Exact IP:            "10.0.1.5"
 *  - CIDR range:          "10.0.0.0/8"
 */
function parseAllowlistEntry(entry: string): AllowlistPattern {
  const normalized = entry.trim().toLowerCase();

  // CIDR range
  if (normalized.includes('/') && !normalized.startsWith('http')) {
    return { type: 'cidr', value: normalized };
  }

  // Wildcard subdomain
  if (normalized.startsWith('*.')) {
    return { type: 'wildcard-hostname', value: normalized.slice(2) };
  }

  // IP address (contains only digits, dots, colons)
  if (/^[\d.:[\]]+$/.test(normalized)) {
    return { type: 'exact-ip', value: normalized };
  }

  // Exact hostname
  return { type: 'exact-hostname', value: normalized };
}

/**
 * Resolve user options into internal ResolvedOptions with defaults applied.
 */
export function resolveOptions(options: SsrfGuardOptions): ResolvedOptions {
  const effectiveBlockedPorts = buildBlockedPortsSet(
    options.blockedPorts,
    options.additionalBlockedPorts,
  );

  const allowlistPatterns: AllowlistPattern[] =
    (options.allowlist ?? []).map(parseAllowlistEntry);

  const isPro =
    typeof options.proLicense === 'string' && options.proLicense.length > 0;

  return {
    urlParam: options.urlParam ?? 'url',
    dnsTimeoutMs: options.dnsTimeoutMs ?? 3000,
    allowOnDnsError: options.allowOnDnsError ?? false,
    exposeReason: options.exposeReason ?? false,
    blockedStatusCode: options.blockedStatusCode ?? 403,
    skipDnsResolution: options.skipDnsResolution ?? false,
    enableDnsRebindingProtection: options.enableDnsRebindingProtection ?? false,
    effectiveBlockedPorts,
    allowlistPatterns,
    isPro,
    raw: options,
  };
}

