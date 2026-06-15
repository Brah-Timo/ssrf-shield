/**
 * Guard Result Types
 * ───────────────────
 * Defines the structured result returned by checkUrl() and the middleware.
 */

import type { ThreatInfo, ThreatCategory } from './threat.js';
import { getThreatSeverity, isLikelyBypassAttempt } from './threat.js';

/**
 * Result of a URL security check.
 * Returned by checkUrl() — the core guard engine.
 */
export interface GuardResult {
  /** Whether the URL is safe to use */
  allowed: boolean;

  /**
   * The normalized, canonical URL string.
   * Present only when allowed = true.
   * Always use this sanitized URL downstream — never the original raw URL.
   */
  safeUrl?: string;

  /**
   * Threat information.
   * Present only when allowed = false.
   */
  threat?: ThreatInfo;

  /**
   * Total time taken for the check (including DNS resolution if any).
   * Useful for monitoring and performance analysis.
   */
  durationMs: number;

  /**
   * Resolved IP addresses from DNS lookup.
   * Present when DNS resolution was performed.
   */
  resolvedIps?: string[];
}

/**
 * Convenience type for a blocked result.
 */
export interface BlockedResult extends GuardResult {
  allowed: false;
  threat: ThreatInfo;
}

/**
 * Convenience type for an allowed result.
 */
export interface AllowedResult extends GuardResult {
  allowed: true;
  safeUrl: string;
}

/**
 * Type guard: checks if a GuardResult is a BlockedResult.
 */
export function isBlocked(result: GuardResult): result is BlockedResult {
  return !result.allowed;
}

/**
 * Type guard: checks if a GuardResult is an AllowedResult.
 */
export function isAllowed(result: GuardResult): result is AllowedResult {
  return result.allowed;
}

/**
 * Build a blocked GuardResult.
 */
export function makeBlockedResult(
  category: ThreatCategory,
  reason: string,
  startTime: number,
  extra?: Partial<ThreatInfo> & { resolvedIps?: string[] },
): BlockedResult {
  return {
    allowed: false,
    durationMs: Date.now() - startTime,
    resolvedIps: extra?.resolvedIps,
    threat: {
      category,
      reason,
      severity: extra?.severity ?? getThreatSeverity(category),
      blockedValue: extra?.blockedValue,
      matchedRange: extra?.matchedRange,
      likelyBypassAttempt: extra?.likelyBypassAttempt ?? isLikelyBypassAttempt(category),
    },
  };
}

/**
 * Build an allowed GuardResult.
 */
export function makeAllowedResult(
  safeUrl: string,
  startTime: number,
  resolvedIps?: string[],
): AllowedResult {
  return {
    allowed: true,
    safeUrl,
    durationMs: Date.now() - startTime,
    resolvedIps,
  };
}

