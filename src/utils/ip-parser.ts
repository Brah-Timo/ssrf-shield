/**
 * IP Parser — Advanced Format Detection & Normalization
 * ──────────────────────────────────────────────────────
 * Attackers encode IP addresses in many exotic formats to bypass naive checks.
 * This module converts all known representations to their canonical dotted-decimal form.
 *
 * Handles all known SSRF IP encoding tricks:
 *
 *  Format            Example              Canonical
 *  ─────────────     ─────────────────    ────────────
 *  Standard          127.0.0.1            127.0.0.1
 *  Decimal integer   2130706433           127.0.0.1
 *  Hexadecimal       0x7f000001           127.0.0.1
 *  Octal             0177.0.0.1           127.0.0.1
 *  Mixed radix       0x7f.0.0.1           127.0.0.1
 *  Leading zeros     127.000.000.001      127.0.0.1
 *  IPv4-in-IPv6      ::ffff:127.0.0.1     127.0.0.1
 *  Bracketed IPv6    [::1]                ::1
 *  Short-form IPv4   127.1                127.0.0.1
 */

export interface ParsedIp {
  /** Canonical dotted-decimal form (IPv4) or colon-hex form (IPv6) */
  canonical: string;
  /** Whether this was an unusual/encoded format (potential bypass attempt) */
  wasEncoded: boolean;
  /** The detected format type */
  format: IpFormat;
  /** Whether this is IPv4 or IPv6 */
  version: 4 | 6;
}

export type IpFormat =
  | 'standard'
  | 'decimal'
  | 'hexadecimal'
  | 'octal'
  | 'mixed'
  | 'leading-zeros'
  | 'ipv4-mapped-ipv6'
  | 'ipv6-bracketed'
  | 'ipv6-short-form'
  | 'ipv4-short-form';

/**
 * Parse and canonicalize an IP address from any known encoding.
 * Returns null if the input is not a recognizable IP format.
 */
export function parseIpAddress(raw: string): ParsedIp | null {
  if (typeof raw !== 'string' || raw.length === 0) {
    return null;
  }

  const cleaned = raw.trim();

  // ── Bracketed IPv6 ────────────────────────────────────────────────────────
  if (cleaned.startsWith('[') && cleaned.endsWith(']')) {
    const inner = cleaned.slice(1, -1);
    const canonical = normalizeIPv6(inner);
    return {
      canonical,
      wasEncoded: inner !== canonical,
      format: 'ipv6-bracketed',
      version: 6,
    };
  }

  // ── Pure IPv6 (contains colons) ───────────────────────────────────────────
  if (cleaned.includes(':') && !cleaned.startsWith('0x')) {
    // Check for IPv4-mapped: ::ffff:127.0.0.1
    if (cleaned.toLowerCase().includes('::ffff:') && cleaned.includes('.')) {
      const v4Part = cleaned.split(':').pop() ?? '';
      const v4Canonical = parseIPv4Dotted(v4Part);
      if (v4Canonical !== null) {
        return {
          canonical: `::ffff:${v4Canonical}`,
          wasEncoded: true,
          format: 'ipv4-mapped-ipv6',
          version: 6,
        };
      }
    }

    const canonical = normalizeIPv6(cleaned);
    return {
      canonical,
      wasEncoded: cleaned !== canonical,
      format: 'ipv6-short-form',
      version: 6,
    };
  }

  // ── Pure decimal integer (e.g. 2130706433) ───────────────────────────────
  if (/^\d+$/.test(cleaned)) {
    const n = parseInt(cleaned, 10);
    if (!isNaN(n) && n >= 0 && n <= 0xffffffff) {
      const canonical = intToIPv4(n);
      return {
        canonical,
        wasEncoded: true,
        format: 'decimal',
        version: 4,
      };
    }
    return null;
  }

  // ── Full hex (e.g. 0x7f000001) ────────────────────────────────────────────
  if (/^0x[0-9a-fA-F]{1,8}$/.test(cleaned)) {
    const n = parseInt(cleaned, 16);
    const canonical = intToIPv4(n);
    return {
      canonical,
      wasEncoded: true,
      format: 'hexadecimal',
      version: 4,
    };
  }

  // ── Dotted notation (may have hex, octal, decimal, or mixed octets) ───────
  if (cleaned.includes('.')) {
    return parseDottedIP(cleaned);
  }

  return null;
}

/**
 * Parse dotted IP address with mixed radix support.
 * Handles: 127.0.0.1, 0177.0.0.1, 0x7f.0.0.1, 127.000.0.001, 127.1
 */
function parseDottedIP(ip: string): ParsedIp | null {
  const parts = ip.split('.');

  // Short-form IPv4 (e.g. 127.1 = 127.0.0.1, 10.0.1 = 10.0.0.1)
  if (parts.length < 4 && parts.length >= 1) {
    return parseShortFormIPv4(parts);
  }

  if (parts.length !== 4) {
    return null;
  }

  let wasEncoded = false;
  let format: IpFormat = 'standard';
  const octets: number[] = [];

  for (const part of parts) {
    if (part === undefined) {
      return null;
    }
    const parsed = parseOctet(part);
    if (parsed === null || parsed.value < 0 || parsed.value > 255) {
      return null;
    }
    if (parsed.wasEncoded) {
      wasEncoded = true;
      format = parsed.format;
    }
    octets.push(parsed.value);
  }

  const canonical = octets.join('.');
  return { canonical, wasEncoded, format, version: 4 };
}

interface OctetResult {
  value: number;
  wasEncoded: boolean;
  format: IpFormat;
}

function parseOctet(s: string): OctetResult | null {
  // Hexadecimal octet: 0x7f, 0XFF
  if (/^0[xX][0-9a-fA-F]+$/.test(s)) {
    return { value: parseInt(s, 16), wasEncoded: true, format: 'hexadecimal' };
  }

  // Octal octet: 0177, 010
  if (/^0[0-7]+$/.test(s) && s.length > 1) {
    return { value: parseInt(s, 8), wasEncoded: true, format: 'octal' };
  }

  // Decimal with leading zeros: 001, 010
  if (/^0\d+$/.test(s)) {
    return { value: parseInt(s, 10), wasEncoded: true, format: 'leading-zeros' };
  }

  // Standard decimal
  if (/^\d+$/.test(s)) {
    return { value: parseInt(s, 10), wasEncoded: false, format: 'standard' };
  }

  return null;
}

function parseShortFormIPv4(parts: string[]): ParsedIp | null {
  if (parts.length === 0 || parts.length > 3) {
    return null;
  }

  // RFC 790 short-form: fewer than 4 octets, last part is multi-byte
  const octets = parts.map((p) => {
    if (p === undefined) {
      return null;
    }
    return parseOctet(p);
  });

  if (octets.some((o) => o === null)) {
    return null;
  }

  const values = (octets as OctetResult[]).map((o) => o.value);
  let ip32 = 0;

  for (let i = 0; i < values.length; i++) {
    const shift = (values.length - 1 - i) * 8;
    const isLast = i === values.length - 1;
    if (isLast && values.length < 4) {
      // Last part holds remaining bytes
      const remainingBits = (4 - values.length + 1) * 8;
      const maxVal = (1 << remainingBits) - 1;
      const val = values[i] ?? 0;
      if (val > maxVal) {
        return null;
      }
      ip32 = ip32 | val;
    } else {
      ip32 = (ip32 | ((values[i] ?? 0) << shift)) >>> 0;
    }
  }

  // Simpler: treat 127.1 as first_octet.(remaining as big-endian int)
  // 127.1 = 127 * 2^24 + 1 = 2130706433
  if (values.length === 2) {
    const a = values[0] ?? 0;
    const b = values[1] ?? 0;
    ip32 = ((a << 24) | b) >>> 0;
  } else if (values.length === 3) {
    const a = values[0] ?? 0;
    const b = values[1] ?? 0;
    const c = values[2] ?? 0;
    ip32 = ((a << 24) | (b << 16) | c) >>> 0;
  }

  return {
    canonical: intToIPv4(ip32),
    wasEncoded: true,
    format: 'ipv4-short-form',
    version: 4,
  };
}

function parseIPv4Dotted(ip: string): string | null {
  const result = parseDottedIP(ip);
  return result?.canonical ?? null;
}

/**
 * Convert a 32-bit integer to dotted-decimal IPv4 string.
 */
export function intToIPv4(n: number): string {
  return [
    (n >>> 24) & 0xff,
    (n >>> 16) & 0xff,
    (n >>> 8) & 0xff,
    n & 0xff,
  ].join('.');
}

/**
 * Normalize an IPv6 address to its canonical expanded form.
 * Uses Node.js built-in URL API for accuracy.
 */
export function normalizeIPv6(ip: string): string {
  try {
    // Wrap in URL to get browser-normalized IPv6
    const url = new URL(`http://[${ip}]/`);
    return url.hostname.replace(/^\[|\]$/g, '');
  } catch {
    return ip.toLowerCase();
  }
}

