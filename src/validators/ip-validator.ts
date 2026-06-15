/**
 * IP Address Validator
 * ─────────────────────
 * The core security check for IP addresses.
 * Handles all known encoding tricks and validates against all blocked ranges.
 *
 * Protects against:
 *  - Direct private IPs:        10.0.0.1, 192.168.1.1
 *  - Loopback:                  127.0.0.1, 127.1, ::1
 *  - Link-local / IMDS:         169.254.169.254
 *  - IPv6 loopback:             ::1, [::1]
 *  - IPv4-mapped IPv6:          ::ffff:127.0.0.1
 *  - Hex encoding:              0x7f000001
 *  - Octal encoding:            0177.0.0.1
 *  - Decimal integer:           2130706433 (= 127.0.0.1)
 *  - Short-form IPv4:           127.1 (= 127.0.0.1)
 *  - Cloud metadata IPs:        169.254.169.254, 100.100.100.200
 */

import ipaddr from 'ipaddr.js';
import { BLOCKED_IPV4_RANGES, BLOCKED_IPV6_RANGES } from '../blocklists/private-ranges.js';
import { CLOUD_METADATA_IPS } from '../blocklists/cloud-metadata.js';
import { isInCIDR } from '../utils/cidr.js';
import { parseIpAddress } from '../utils/ip-parser.js';
import type { ThreatCategory } from '../types/threat.js';

export interface IpCheckResult {
  /** Whether the IP is blocked */
  blocked: boolean;
  /** Human-readable reason for the block */
  reason?: string;
  /** Machine-readable threat category */
  threatCategory?: ThreatCategory;
  /** The canonical (normalized) IP that was checked */
  canonicalIp: string;
  /** Whether the input used an encoding trick */
  wasEncoded: boolean;
  /** The CIDR range that matched, if any */
  matchedRange?: string;
}

/**
 * Check whether an IP address (in any format) is safe for outbound requests.
 *
 * Handles all known bypass encodings including hex, octal, decimal integer,
 * short-form, IPv6-mapped-IPv4, and bracketed IPv6.
 *
 * @param rawIp - Raw IP string from URL hostname (may be encoded)
 * @returns IpCheckResult with block status and threat details
 */
export function checkIpAddress(rawIp: string): IpCheckResult {
  // ── Clean up brackets around IPv6 ─────────────────────────────────────────
  const cleaned = rawIp.replace(/^\[|\]$/g, '').trim();

  // ── Try advanced parser first (handles hex/octal/decimal/short-form) ───────
  const advanced = parseIpAddress(cleaned);
  const canonicalIp = advanced?.canonical ?? cleaned;
  const wasEncoded = advanced?.wasEncoded ?? false;

  // ── Try ipaddr.js for proper IPv4/IPv6 parsing ────────────────────────────
  let addr: ipaddr.IPv4 | ipaddr.IPv6;
  try {
    addr = ipaddr.parse(canonicalIp);
  } catch {
    // If ipaddr.js can't parse it but our parser produced a canonical form, try again
    try {
      addr = ipaddr.parse(cleaned);
    } catch {
      return {
        blocked: true,
        reason: `Cannot parse IP address: "${rawIp}"`,
        threatCategory: 'INVALID_URL',
        canonicalIp: cleaned,
        wasEncoded: false,
      };
    }
  }

  // ── Convert IPv4-mapped IPv6 to plain IPv4 ────────────────────────────────
  // ::ffff:127.0.0.1 is localhost disguised as IPv6
  let normalizedAddr = addr;
  let ipVersion: 4 | 6 = addr.kind() === 'ipv4' ? 4 : 6;
  let wasIpv4Mapped = false;

  if (addr.kind() === 'ipv6') {
    const v6 = addr as ipaddr.IPv6;
    if (v6.isIPv4MappedAddress()) {
      normalizedAddr = v6.toIPv4Address();
      ipVersion = 4;
      wasIpv4Mapped = true;
    }
  }

  const normalizedIp = normalizedAddr.toString();

  // ── Cloud metadata check (highest priority) ─────────────────────────────
  if (CLOUD_METADATA_IPS.has(normalizedIp) || CLOUD_METADATA_IPS.has(cleaned)) {
    return {
      blocked: true,
      reason: `Cloud metadata endpoint blocked: ${normalizedIp}`,
      threatCategory: 'CLOUD_METADATA',
      canonicalIp: normalizedIp,
      wasEncoded: wasEncoded || wasIpv4Mapped,
    };
  }

  // ── Check against blocked CIDR ranges ─────────────────────────────────────
  const ranges = ipVersion === 4 ? BLOCKED_IPV4_RANGES : BLOCKED_IPV6_RANGES;

  for (const range of ranges) {
    if (isInCIDR(normalizedIp, range.cidr)) {
      return {
        blocked: true,
        reason: `IP ${normalizedIp} is in blocked range ${range.cidr} (${range.label})`,
        threatCategory: classifyByLabel(range.label),
        canonicalIp: normalizedIp,
        wasEncoded: wasEncoded || wasIpv4Mapped,
        matchedRange: range.cidr,
      };
    }
  }

  // If it was IPv4-mapped-IPv6, that itself is suspicious even if the underlying
  // IP wasn't in a blocked range — still mark it
  return {
    blocked: false,
    canonicalIp: normalizedIp,
    wasEncoded: wasEncoded || wasIpv4Mapped,
  };
}

/**
 * Map a range label to a structured ThreatCategory.
 */
function classifyByLabel(label: string): ThreatCategory {
  const lower = label.toLowerCase();
  if (lower.includes('loopback')) {
    return 'LOOPBACK';
  }
  if (lower.includes('link-local') || lower.includes('cloud metadata')) {
    return 'LINK_LOCAL';
  }
  if (lower.includes('private') || lower.includes('rfc1918')) {
    return 'PRIVATE_IP';
  }
  if (lower.includes('multicast')) {
    return 'MULTICAST';
  }
  if (lower.includes('unspecified')) {
    return 'UNSPECIFIED';
  }
  if (lower.includes('shared') || lower.includes('cgn')) {
    return 'SHARED_ADDRESS_SPACE';
  }
  if (lower.includes('ipv4-mapped')) {
    return 'IPV6_MAPPED_IPV4';
  }
  return 'PRIVATE_IP';
}

/**
 * Quick helper: returns true if the IP should be blocked.
 * Convenience wrapper around checkIpAddress().
 */
export function isBlockedIp(rawIp: string): boolean {
  return checkIpAddress(rawIp).blocked;
}

