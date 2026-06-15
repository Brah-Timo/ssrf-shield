/**
 * URL Structural Validator
 * ─────────────────────────
 * Validates the structure and components of a URL before deeper checks.
 * Runs after url-normalizer, before IP/DNS checks.
 *
 * Catches:
 *  - Malformed URLs
 *  - Dangerous schemes (delegated to scheme validator)
 *  - Suspiciously long URLs (DoS / parser confusion)
 *  - Empty hostnames
 *  - Non-standard port numbers
 *  - URL with embedded newlines/control characters after decoding
 */

import { parseNormalizedUrl, InvalidUrlError, isDirectIp } from '../utils/url-normalizer.js';
import { validateScheme } from '../blocklists/dangerous-schemes.js';
import { isCloudMetadataHost } from '../blocklists/cloud-metadata.js';
import type { ThreatCategory } from '../types/threat.js';

export interface UrlValidationResult {
  valid: boolean;
  normalizedUrl?: string;
  parsed?: URL;
  hostname?: string;
  isDirectIpAddress: boolean;
  port: number;
  reason?: string;
  threatCategory?: ThreatCategory;
}

/**
 * Maximum URL length we accept. Longer URLs are rejected.
 * 8KB is generous for any legitimate URL; above that is likely an attack.
 */
const MAX_URL_LENGTH = 8192;

/**
 * Validate the structure and scheme of a raw URL.
 * This is the first substantive check after normalization.
 *
 * @returns UrlValidationResult with parsed components on success
 */
export function validateUrl(rawUrl: string): UrlValidationResult {
  // ── Length guard ───────────────────────────────────────────────────────────
  if (typeof rawUrl !== 'string') {
    return fail('URL must be a string', 'INVALID_URL');
  }
  if (rawUrl.trim().length === 0) {
    return fail('URL cannot be empty', 'INVALID_URL');
  }
  if (rawUrl.length > MAX_URL_LENGTH) {
    return fail(
      `URL exceeds maximum length of ${MAX_URL_LENGTH} characters`,
      'INVALID_URL',
    );
  }

  // ── Parse and normalize ────────────────────────────────────────────────────
  let parsed: URL;
  let normalizedUrl: string;
  try {
    parsed = parseNormalizedUrl(rawUrl);
    normalizedUrl = parsed.toString();
  } catch (err) {
    if (err instanceof InvalidUrlError) {
      return fail(`Invalid URL: ${err.message}`, 'INVALID_URL');
    }
    return fail('URL parsing failed', 'INVALID_URL');
  }

  // ── Scheme validation ──────────────────────────────────────────────────────
  try {
    validateScheme(parsed.protocol);
  } catch (err: unknown) {
    const scheme = parsed.protocol.replace(/:$/, '').toLowerCase();
    return fail(
      `Blocked scheme: "${scheme}". Only HTTP and HTTPS are permitted.`,
      'BLOCKED_SCHEME',
    );
  }

  // ── Hostname must exist ────────────────────────────────────────────────────
  const hostname = parsed.hostname;
  if (!hostname || hostname.length === 0) {
    return fail('URL has no hostname', 'INVALID_URL');
  }

  // ── Check for suspicious hostname characters (post-normalization) ──────────
  // After normalization, hostnames should only contain valid chars
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(hostname)) {
    return fail('Hostname contains control characters', 'INVALID_URL');
  }

  // ── Cloud metadata hostname check ─────────────────────────────────────────
  if (isCloudMetadataHost(hostname)) {
    return fail(
      `Cloud metadata hostname blocked: "${hostname}"`,
      'CLOUD_METADATA_HOSTNAME',
    );
  }

  // ── Determine effective port ───────────────────────────────────────────────
  let port: number;
  if (parsed.port !== '') {
    port = parseInt(parsed.port, 10);
    if (isNaN(port) || port < 0 || port > 65535) {
      return fail(`Invalid port: "${parsed.port}"`, 'INVALID_URL');
    }
  } else {
    // Default ports
    port = parsed.protocol === 'https:' ? 443 : 80;
  }

  // ── Determine if hostname is a direct IP ──────────────────────────────────
  const directIp = isDirectIp(hostname);

  return {
    valid: true,
    normalizedUrl,
    parsed,
    hostname,
    isDirectIpAddress: directIp,
    port,
  };
}

function fail(reason: string, threatCategory: ThreatCategory): UrlValidationResult {
  return {
    valid: false,
    isDirectIpAddress: false,
    port: 0,
    reason,
    threatCategory,
  };
}

