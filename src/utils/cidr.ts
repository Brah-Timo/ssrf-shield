/**
 * CIDR Utilities
 * ──────────────
 * Pure TypeScript implementation of CIDR range matching.
 * No external dependencies — works for both IPv4 and IPv6.
 *
 * Supports:
 *  - IPv4 CIDR:  "192.168.0.0/16"
 *  - IPv6 CIDR:  "fe80::/10"
 *  - Single IPs: "127.0.0.1/32", "::1/128"
 */

export interface CIDRRange {
  /** CIDR notation, e.g. "10.0.0.0/8" */
  cidr: string;
  /** Human-readable label for error messages */
  label: string;
}

// ─── IPv4 helpers ────────────────────────────────────────────────────────────

/**
 * Convert a dotted-decimal IPv4 string to a 32-bit unsigned integer.
 * e.g. "192.168.1.1" → 3232235777
 */
export function ipv4ToInt(ip: string): number {
  const parts = ip.split('.');
  if (parts.length !== 4) {
    throw new TypeError(`Invalid IPv4 address: ${ip}`);
  }
  return (
    ((parseInt(parts[0] ?? '0', 10) << 24) |
      (parseInt(parts[1] ?? '0', 10) << 16) |
      (parseInt(parts[2] ?? '0', 10) << 8) |
      parseInt(parts[3] ?? '0', 10)) >>>
    0
  );
}

/**
 * Check if an IPv4 address string falls within a CIDR range.
 */
export function isIPv4InCIDR(ip: string, cidr: string): boolean {
  const [networkStr, prefixStr] = cidr.split('/');
  if (networkStr === undefined || prefixStr === undefined) {
    throw new TypeError(`Invalid CIDR notation: ${cidr}`);
  }
  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 32) {
    throw new TypeError(`Invalid CIDR prefix length: ${prefixStr}`);
  }

  const mask = prefix === 0 ? 0 : (~0 << (32 - prefix)) >>> 0;
  const networkInt = ipv4ToInt(networkStr) & mask;
  const ipInt = ipv4ToInt(ip) & mask;

  return networkInt === ipInt;
}

// ─── IPv6 helpers ─────────────────────────────────────────────────────────────

/**
 * Expand a possibly compressed IPv6 address to its full 8-group form.
 * e.g. "::1" → "0000:0000:0000:0000:0000:0000:0000:0001"
 */
export function expandIPv6(ip: string): string {
  // Handle IPv4-mapped IPv6 (::ffff:192.0.2.1)
  if (ip.includes('.')) {
    const v4Part = ip.split(':').pop() ?? '';
    const v4Parts = v4Part.split('.');
    const prefix = ip.substring(0, ip.lastIndexOf(':') + 1);
    const high = (parseInt(v4Parts[0] ?? '0', 10) << 8) | parseInt(v4Parts[1] ?? '0', 10);
    const low = (parseInt(v4Parts[2] ?? '0', 10) << 8) | parseInt(v4Parts[3] ?? '0', 10);
    ip = `${prefix}${high.toString(16)}:${low.toString(16)}`;
  }

  // Expand "::"
  if (ip.includes('::')) {
    const parts = ip.split('::');
    const left = parts[0] ?? '';
    const right = parts[1] ?? '';
    const leftGroups = left !== '' ? left.split(':') : [];
    const rightGroups = right !== '' ? right.split(':') : [];
    const missing = 8 - leftGroups.length - rightGroups.length;
    const middle: string[] = Array.from({ length: missing }, () => '0000');
    const groups: string[] = [...leftGroups, ...middle, ...rightGroups];
    return groups.map((g) => g.padStart(4, '0')).join(':');
  }

  return ip
    .split(':')
    .map((g) => g.padStart(4, '0'))
    .join(':');
}

/**
 * Convert a full 8-group IPv6 string to a BigInt (128-bit).
 */
export function ipv6ToBigInt(ip: string): bigint {
  const expanded = expandIPv6(ip);
  const groups = expanded.split(':');
  return groups.reduce((acc, group) => (acc << 16n) | BigInt(parseInt(group, 16)), 0n);
}

/**
 * Check if an IPv6 address falls within a CIDR range.
 */
export function isIPv6InCIDR(ip: string, cidr: string): boolean {
  const [networkStr, prefixStr] = cidr.split('/');
  if (networkStr === undefined || prefixStr === undefined) {
    throw new TypeError(`Invalid CIDR notation: ${cidr}`);
  }
  const prefix = parseInt(prefixStr, 10);
  if (isNaN(prefix) || prefix < 0 || prefix > 128) {
    throw new TypeError(`Invalid CIDR prefix length: ${prefixStr}`);
  }

  if (prefix === 0) {
    return true; // ::/0 matches everything
  }

  const mask = ((1n << BigInt(128 - prefix)) - 1n) ^ ((1n << 128n) - 1n);
  const networkInt = ipv6ToBigInt(networkStr) & mask;
  const ipInt = ipv6ToBigInt(ip) & mask;

  return networkInt === ipInt;
}

// ─── Unified entry point ──────────────────────────────────────────────────────

/**
 * Check if an IP (v4 or v6) falls within a CIDR range.
 * Automatically detects IP version from the CIDR notation.
 */
export function isInCIDR(ip: string, cidr: string): boolean {
  try {
    if (cidr.includes(':')) {
      // IPv6 CIDR
      return isIPv6InCIDR(ip, cidr);
    } else {
      // IPv4 CIDR
      return isIPv4InCIDR(ip, cidr);
    }
  } catch {
    return false; // Malformed input → not in range (safe default)
  }
}

