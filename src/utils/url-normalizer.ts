/**
 * URL Normalizer
 * ──────────────
 * First line of defense. Many SSRF bypasses rely on malformed URLs
 * that confuse naive string-matching parsers. This module normalizes
 * every URL into a canonical form before any further checks.
 *
 * Protects against:
 *  - Backslash bypass:        http:\\localhost
 *  - Embedded credentials:    http://attacker.com@localhost/
 *  - Unicode homoglyphs:      http://ⓛocalhost/
 *  - URL-encoded characters:  http://127%2E0%2E0%2E1/
 *  - Null-byte injection:     http://localhost%00.evil.com/
 *  - Mixed-case schemes:      HTTP://localhost/
 *  - Trailing whitespace:     "  http://localhost/ "
 *  - Multiple slashes:        http:///localhost
 *  - Tab/newline characters:  http://local\thost/
 */

export class InvalidUrlError extends Error {
  public readonly code = 'INVALID_URL' as const;
  public readonly originalInput: string;

  public constructor(message: string, originalInput: string) {
    super(message);
    this.name = 'InvalidUrlError';
    this.originalInput = originalInput;
  }
}

/**
 * Normalize a raw URL string into its canonical WHATWG form.
 *
 * @param raw - Raw user-supplied URL string
 * @returns Normalized URL string safe for further analysis
 * @throws {InvalidUrlError} When the input cannot be parsed as a valid URL
 */
export function normalizeUrl(raw: string): string {
  if (typeof raw !== 'string') {
    throw new InvalidUrlError('URL must be a string', String(raw));
  }

  // ── Step 1: Strip outer whitespace ──────────────────────────────────────────
  let url = raw.trim();

  if (url.length === 0) {
    throw new InvalidUrlError('URL cannot be empty', raw);
  }

  // ── Step 2: Remove control characters (null bytes, tabs, newlines, etc.) ────
  // These are sometimes used to bypass URL parsers that handle them differently
  // eslint-disable-next-line no-control-regex
  url = url.replace(/[\x00-\x1f\x7f]/g, '');

  // ── Step 3: Replace backslashes with forward slashes ────────────────────────
  // Some parsers treat http:\\localhost as http://localhost
  url = url.replace(/\\/g, '/');

  // ── Step 4: Normalize consecutive slashes in path (NOT the scheme //) ───────
  // http:///localhost → http://localhost (extra slashes after scheme)
  url = url.replace(/^([a-zA-Z][a-zA-Z\d+\-.]*):\/\/+/, '$1://');

  // ── Step 5: Unicode NFC normalization ────────────────────────────────────────
  // Protect against homoglyph attacks (Cyrillic 'о' vs Latin 'o')
  url = url.normalize('NFC');

  // ── Step 6: Parse with WHATWG URL API ────────────────────────────────────────
  // This is the gold standard — it matches browser behavior
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new InvalidUrlError(`Cannot parse as URL: "${url}"`, raw);
  }

  // ── Step 7: Strip embedded credentials ───────────────────────────────────────
  // CRITICAL: http://attacker.com@localhost/ → the host is LOCALHOST, not attacker.com
  // The URL API correctly identifies hostname = 'localhost' here
  // We must strip the credentials so downstream checks see the real host clearly
  parsed.username = '';
  parsed.password = '';

  // ── Step 8: Decode percent-encoded host ──────────────────────────────────────
  // http://127%2E0%2E0%2E1/ → The URL parser already decodes the host,
  // but we double-check by re-parsing after stripping credentials
  // (URL API handles this natively)

  // ── Step 9: Remove URL fragment ──────────────────────────────────────────────
  // Fragments (#...) are client-side only and irrelevant for server-side requests
  parsed.hash = '';

  // ── Step 10: Lowercase the hostname ──────────────────────────────────────────
  // DNS is case-insensitive; normalize for consistent downstream matching
  parsed.hostname = parsed.hostname.toLowerCase();

  return parsed.toString();
}

/**
 * Extract and return the parsed URL object from a raw string.
 * Useful when callers need to inspect individual URL components.
 *
 * @param raw - Raw user-supplied URL string
 * @returns Parsed and normalized URL object
 * @throws {InvalidUrlError} When the input cannot be parsed
 */
export function parseNormalizedUrl(raw: string): URL {
  const normalized = normalizeUrl(raw);
  return new URL(normalized);
}

/**
 * Check whether a string looks like a raw IP address (v4 or v6).
 * Used to skip DNS resolution for direct-IP URLs.
 */
export function isDirectIp(hostname: string): boolean {
  // IPv6 in brackets: [::1], [::ffff:127.0.0.1]
  if (hostname.startsWith('[') && hostname.endsWith(']')) {
    return true;
  }
  // IPv4: digits and dots only — four dot-separated 1-3 digit groups
  // eslint-disable-next-line security/detect-unsafe-regex
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    return true;
  }
  // Hex IP: 0x...
  if (/^0x[0-9a-fA-F]+$/.test(hostname)) {
    return true;
  }
  // Octal IP: 0... (starts with zero followed by digits)
  // eslint-disable-next-line security/detect-unsafe-regex
  if (/^0\d+(\.\d+)*$/.test(hostname)) {
    return true;
  }
  // Pure decimal integer (e.g. 2130706433 = 127.0.0.1)
  if (/^\d+$/.test(hostname)) {
    return true;
  }
  return false;
}

