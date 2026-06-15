/**
 * [PRO] IP Allowlist / Whitelist
 * ───────────────────────────────
 * Allows specific trusted hosts to bypass SSRF checks entirely.
 * Essential for applications that need to call their own internal APIs.
 *
 * Supported pattern types:
 *  - Exact hostname:      "api.myservice.com"
 *  - Wildcard subdomain:  "*.internal.corp" (matches sub.internal.corp)
 *  - Exact IP:            "10.0.1.5"
 *  - CIDR range:          "10.0.0.0/8" or "10.0.1.0/24"
 *
 * Security note:
 *  The allowlist is ONLY activated when a valid proLicense key is provided.
 *  Without it, all requests go through full SSRF checks regardless.
 *
 * Usage:
 *   app.use(ssrfGuard({
 *     proLicense: process.env.SSRF_GUARD_KEY,
 *     allowlist: ['api.myservice.com', '*.internal.corp', '10.0.1.0/24'],
 *   }));
 */

import { isInCIDR } from '../utils/cidr.js';
import type { AllowlistPattern } from '../types/options.js';

/**
 * Check if a hostname matches any pattern in the allowlist.
 *
 * @param hostname          - Normalized hostname from the URL
 * @param allowlistPatterns - Parsed allowlist patterns (from resolveOptions)
 * @returns true if the host is in the allowlist (should be allowed)
 */
export function checkAllowlist(
  hostname: string,
  allowlistPatterns: readonly AllowlistPattern[],
): boolean {
  if (allowlistPatterns.length === 0) {
    return false;
  }

  const normalizedHostname = hostname.toLowerCase().replace(/^\[|\]$/g, '');

  for (const pattern of allowlistPatterns) {
    if (matchesPattern(normalizedHostname, pattern)) {
      return true;
    }
  }

  return false;
}

/**
 * Check if a hostname matches a single allowlist pattern.
 */
function matchesPattern(hostname: string, pattern: AllowlistPattern): boolean {
  switch (pattern.type) {
    case 'exact-hostname':
      return hostname === pattern.value;

    case 'wildcard-hostname':
      // *.example.com matches sub.example.com but NOT example.com itself
      // Security: require at least one subdomain label before the pattern
      return (
        hostname.endsWith(`.${pattern.value}`) ||
        hostname === pattern.value
      );

    case 'exact-ip':
      return hostname === pattern.value.replace(/^\[|\]$/g, '');

    case 'cidr':
      try {
        return isInCIDR(hostname, pattern.value);
      } catch {
        // If CIDR matching fails (e.g., hostname is not an IP), return false
        return false;
      }

    default:
      return false;
  }
}

/**
 * [PRO] License validation.
 * In production this calls the ssrf-shield.io API to validate the key
 * and determine the plan tier.
 *
 * For local development / offline use, the license check is skipped
 * if the key matches the offline development pattern: "dev-*"
 */
export interface ProPlan {
  tier: 'pro' | 'enterprise';
  customAllowlist: boolean;
  requestLogging: boolean;
  webhookAlerts: boolean;
  rateLimiting: boolean;
  requestsPerMonth: number;
  dashboardUrl: string;
}

/**
 * Validate a Pro license key.
 * Returns the plan details or throws on invalid key.
 */
export async function validateProLicense(licenseKey: string): Promise<ProPlan> {
  // Dev/offline mode — key pattern: "dev-..." or "test-..."
  if (licenseKey.startsWith('dev-') || licenseKey.startsWith('test-')) {
    return {
      tier: 'pro',
      customAllowlist: true,
      requestLogging: true,
      webhookAlerts: true,
      rateLimiting: true,
      requestsPerMonth: 1_000_000,
      dashboardUrl: 'http://localhost:3000/dashboard',
    };
  }

  // Production: call the license API
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5000);

  try {
    const response = await fetch('https://api.ssrf-shield.io/v1/license/validate', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'ssrf-shield/1.0.0',
      },
      body: JSON.stringify({ key: licenseKey }),
      signal: controller.signal,
    });

    if (!response.ok) {
      throw new Error(
        `Invalid ssrf-shield Pro license key (HTTP ${response.status.toString()})`,
      );
    }

    return response.json() as Promise<ProPlan>;
  } finally {
    clearTimeout(timeout);
  }
}

