/**
 * Threat Classification Types
 * ────────────────────────────
 * Enumerates every category of SSRF threat that ssrf-shield can detect.
 * Used for structured logging, alerting, and analytics.
 */

/**
 * Broad threat category — used in API responses and logs.
 */
export type ThreatCategory =
  | 'BLOCKED_SCHEME'          // Dangerous protocol (file://, gopher://, etc.)
  | 'BLOCKED_PORT'            // Internal service port (Redis, MongoDB, SSH, etc.)
  | 'PRIVATE_IP'              // RFC 1918 private address
  | 'LOOPBACK'                // 127.x.x.x or ::1
  | 'LINK_LOCAL'              // 169.254.x.x
  | 'CLOUD_METADATA'          // AWS/GCP/Azure metadata endpoint
  | 'IPV6_MAPPED_IPV4'        // ::ffff:127.0.0.1 (disguised IPv4)
  | 'MULTICAST'               // 224.0.0.0/4, ff00::/8
  | 'UNSPECIFIED'             // 0.0.0.0
  | 'DNS_RESOLVED_PRIVATE'    // Hostname resolved to a private IP
  | 'DNS_REBINDING'           // DNS changed between checks (rebinding attack)
  | 'DNS_TIMEOUT'             // DNS resolution timed out (fail-safe block)
  | 'DNS_ERROR'               // Generic DNS resolution failure
  | 'INVALID_URL'             // URL cannot be parsed / malformed
  | 'ENCODED_IP'              // Hex/octal/decimal IP encoding trick
  | 'SHARED_ADDRESS_SPACE'    // RFC 6598 CGN (100.64.0.0/10)
  | 'CLOUD_METADATA_HOSTNAME' // metadata.google.internal etc.
  | 'UNKNOWN';                // Fallback (should not occur)

/**
 * Detailed threat information returned in GuardResult.
 */
export interface ThreatInfo {
  /** Broad category for routing to dashboards / alert rules */
  category: ThreatCategory;

  /** Human-readable explanation of why this was blocked */
  reason: string;

  /**
   * Severity rating:
   *  critical = active exploitation of SSRF for credential theft
   *  high     = internal network access / service enumeration
   *  medium   = potential internal access, lower confidence
   *  low      = suspicious but not confirmed malicious
   */
  severity: 'critical' | 'high' | 'medium' | 'low';

  /** The IP or hostname that triggered the block (if applicable) */
  blockedValue?: string;

  /** The CIDR range that matched (if applicable) */
  matchedRange?: string;

  /** Whether this looks like an intentional bypass attempt */
  likelyBypassAttempt: boolean;
}

/**
 * Classify threat severity based on category.
 */
export function getThreatSeverity(
  category: ThreatCategory,
): ThreatInfo['severity'] {
  switch (category) {
    case 'CLOUD_METADATA':
    case 'CLOUD_METADATA_HOSTNAME':
    case 'LOOPBACK':
    case 'DNS_REBINDING':
      return 'critical';

    case 'PRIVATE_IP':
    case 'LINK_LOCAL':
    case 'BLOCKED_SCHEME':
    case 'DNS_RESOLVED_PRIVATE':
    case 'IPV6_MAPPED_IPV4':
      return 'high';

    case 'BLOCKED_PORT':
    case 'ENCODED_IP':
    case 'SHARED_ADDRESS_SPACE':
    case 'DNS_TIMEOUT':
    case 'DNS_ERROR':
      return 'medium';

    case 'MULTICAST':
    case 'UNSPECIFIED':
    case 'INVALID_URL':
    case 'UNKNOWN':
    default:
      return 'low';
  }
}

/**
 * Determine if a blocked request looks like an intentional bypass attempt
 * (as opposed to a misconfigured legitimate request).
 */
export function isLikelyBypassAttempt(category: ThreatCategory): boolean {
  const bypassCategories = new Set<ThreatCategory>([
    'ENCODED_IP',
    'IPV6_MAPPED_IPV4',
    'DNS_REBINDING',
    'CLOUD_METADATA',
    'BLOCKED_SCHEME',
  ]);
  return bypassCategories.has(category);
}

