/**
 * Private & Reserved IP Ranges
 * ──────────────────────────────
 * Comprehensive list of all IPv4/IPv6 ranges that must be blocked
 * to prevent SSRF attacks.
 *
 * Sources:
 *  - IANA IPv4 Special-Purpose Address Registry
 *    https://www.iana.org/assignments/iana-ipv4-special-registry/
 *  - IANA IPv6 Special-Purpose Address Registry
 *    https://www.iana.org/assignments/iana-ipv6-special-registry/
 *  - RFC 5735, RFC 6598, RFC 6890
 *  - Cloud provider metadata documentation
 *
 * Last updated: 2024
 */

import type { CIDRRange } from '../utils/cidr.js';

// ─── IPv4 Blocked Ranges ──────────────────────────────────────────────────────

export const BLOCKED_IPV4_RANGES: readonly CIDRRange[] = [
  // ── Loopback ────────────────────────────────────────────────────────────────
  { cidr: '127.0.0.0/8', label: 'Loopback (localhost)' },

  // ── Unspecified ─────────────────────────────────────────────────────────────
  { cidr: '0.0.0.0/8', label: 'Unspecified (this network)' },
  { cidr: '0.0.0.0/32', label: 'Unspecified address' },

  // ── RFC 1918 — Private Networks ──────────────────────────────────────────────
  { cidr: '10.0.0.0/8', label: 'RFC1918 Private Class A' },
  { cidr: '172.16.0.0/12', label: 'RFC1918 Private Class B' },
  { cidr: '192.168.0.0/16', label: 'RFC1918 Private Class C' },

  // ── Link-Local — Cloud Metadata (CRITICAL) ───────────────────────────────────
  // AWS IMDS: 169.254.169.254
  // Azure IMDS: 169.254.169.254
  // GCP IMDS: 169.254.169.254 (also metadata.google.internal)
  { cidr: '169.254.0.0/16', label: 'Link-Local / Cloud Metadata (IMDS)' },

  // ── Shared Address Space — RFC 6598 (CGN) ────────────────────────────────────
  { cidr: '100.64.0.0/10', label: 'Shared Address Space (RFC6598 CGN)' },

  // ── Documentation / TEST-NET ─────────────────────────────────────────────────
  { cidr: '192.0.2.0/24', label: 'Documentation TEST-NET-1 (RFC5737)' },
  { cidr: '198.51.100.0/24', label: 'Documentation TEST-NET-2 (RFC5737)' },
  { cidr: '203.0.113.0/24', label: 'Documentation TEST-NET-3 (RFC5737)' },

  // ── IETF Protocol Assignments ────────────────────────────────────────────────
  { cidr: '192.0.0.0/24', label: 'IETF Protocol Assignments (RFC6890)' },

  // ── 6to4 Relay Anycast ───────────────────────────────────────────────────────
  { cidr: '192.88.99.0/24', label: '6to4 Relay Anycast (RFC3068, deprecated)' },

  // ── Benchmarking / Testing ───────────────────────────────────────────────────
  { cidr: '198.18.0.0/15', label: 'Benchmarking (RFC2544)' },

  // ── Multicast ────────────────────────────────────────────────────────────────
  { cidr: '224.0.0.0/4', label: 'Multicast (RFC1112)' },

  // ── Reserved / Future / Broadcast ───────────────────────────────────────────
  { cidr: '240.0.0.0/4', label: 'Reserved for Future Use' },
  { cidr: '255.255.255.255/32', label: 'Broadcast' },
] as const;

// ─── IPv6 Blocked Ranges ──────────────────────────────────────────────────────

export const BLOCKED_IPV6_RANGES: readonly CIDRRange[] = [
  // ── Loopback ────────────────────────────────────────────────────────────────
  { cidr: '::1/128', label: 'IPv6 Loopback' },

  // ── Unspecified ─────────────────────────────────────────────────────────────
  { cidr: '::/128', label: 'IPv6 Unspecified' },

  // ── Link-Local ───────────────────────────────────────────────────────────────
  { cidr: 'fe80::/10', label: 'IPv6 Link-Local' },

  // ── Unique Local (RFC4193) — IPv6 equivalent of RFC1918 ─────────────────────
  { cidr: 'fc00::/7', label: 'IPv6 Unique Local (RFC4193)' },

  // ── IPv4-mapped IPv6 — CRITICAL bypass vector ───────────────────────────────
  // ::ffff:127.0.0.1 resolves to 127.0.0.1 — localhost!
  { cidr: '::ffff:0:0/96', label: 'IPv4-mapped IPv6 (RFC4291)' },

  // ── IPv4-translated IPv6 ─────────────────────────────────────────────────────
  { cidr: '::ffff:0:0:0/96', label: 'IPv4-translated IPv6 (RFC6145)' },

  // ── IPv4/IPv6 translation ────────────────────────────────────────────────────
  { cidr: '64:ff9b::/96', label: 'IPv4/IPv6 translation (RFC6052)' },
  { cidr: '64:ff9b:1::/48', label: 'IPv4/IPv6 translation (RFC8215)' },

  // ── Discard-only address block ───────────────────────────────────────────────
  { cidr: '100::/64', label: 'Discard-only (RFC6666)' },

  // ── IETF Protocol Assignments ────────────────────────────────────────────────
  { cidr: '2001::/23', label: 'IETF Protocol Assignments (RFC2928)' },

  // ── Teredo ───────────────────────────────────────────────────────────────────
  { cidr: '2001::/32', label: 'Teredo Tunneling (RFC4380)' },

  // ── ORCHIDv2 ─────────────────────────────────────────────────────────────────
  { cidr: '2001:20::/28', label: 'ORCHIDv2 (RFC7343)' },

  // ── Documentation ────────────────────────────────────────────────────────────
  { cidr: '2001:db8::/32', label: 'Documentation (RFC3849)' },

  // ── 6to4 ─────────────────────────────────────────────────────────────────────
  { cidr: '2002::/16', label: '6to4 (RFC3056)' },

  // ── Multicast ────────────────────────────────────────────────────────────────
  { cidr: 'ff00::/8', label: 'IPv6 Multicast (RFC4291)' },

  // ── AWS IPv6 Metadata ────────────────────────────────────────────────────────
  { cidr: 'fd00:ec2::/32', label: 'AWS IPv6 Instance Metadata' },
] as const;

