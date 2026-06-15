/**
 * [PRO] Rate Limiter
 * ───────────────────
 * Per-IP rate limiting for the SSRF check endpoint.
 * Prevents brute-force enumeration of your internal network topology.
 *
 * Algorithm: Fixed window counter (per IP, per time window)
 *
 * Why rate-limit SSRF checks specifically?
 *  An attacker can automate scanning: send thousands of different internal
 *  IPs to your /fetch endpoint, observe which ones return 200 vs 403,
 *  and map your internal network. Rate limiting makes this prohibitively slow.
 *
 * Features:
 *  - In-memory store (fast, zero dependencies)
 *  - Automatic cleanup of expired windows (no memory leak)
 *  - Configurable window size and max requests
 *  - IP extraction supports X-Forwarded-For (configurable trust level)
 *
 * For distributed/multi-process applications, use Redis-backed rate limiting
 * via the ssrf-shield Pro Redis adapter: import from 'ssrf-shield/pro/redis-limiter'
 */

export interface RateLimiterOptions {
  /** Maximum requests allowed per IP per window. Default: 100 */
  maxRequests?: number;
  /** Window size in seconds. Default: 60 */
  windowSecs?: number;
  /** Whether to trust X-Forwarded-For header. Default: false (use socket IP) */
  trustForwardedFor?: boolean;
  /** How many hops to trust in X-Forwarded-For (1 = rightmost proxy). Default: 1 */
  trustedHops?: number;
}

export interface RateLimitResult {
  /** Whether the request is allowed under the rate limit */
  allowed: boolean;
  /** Requests made in the current window */
  count: number;
  /** Maximum requests allowed */
  limit: number;
  /** Unix timestamp when the current window resets */
  resetAt: number;
  /** Remaining requests in the current window */
  remaining: number;
}

interface WindowEntry {
  count: number;
  windowStart: number;
}

/**
 * In-memory rate limiter for SSRF check requests.
 *
 * Usage:
 *   const limiter = new SsrfRateLimiter({ maxRequests: 50, windowSecs: 60 });
 *
 *   app.use((req, res, next) => {
 *     const ip = req.ip ?? 'unknown';
 *     const result = limiter.check(ip);
 *     if (!result.allowed) {
 *       return res.status(429).json({ error: 'Too many requests' });
 *     }
 *     next();
 *   });
 */
export class SsrfRateLimiter {
  private readonly store = new Map<string, WindowEntry>();
  private readonly maxRequests: number;
  private readonly windowMs: number;
  private cleanupTimer: ReturnType<typeof setInterval> | null = null;

  public constructor(options: RateLimiterOptions = {}) {
    this.maxRequests = options.maxRequests ?? 100;
    this.windowMs = (options.windowSecs ?? 60) * 1000;
    this.startCleanup();
  }

  /**
   * Check and record a request from the given IP.
   *
   * @param ip - Source IP address (already extracted from request)
   * @returns RateLimitResult
   */
  public check(ip: string): RateLimitResult {
    const now = Date.now();
    const windowStart = Math.floor(now / this.windowMs) * this.windowMs;
    const resetAt = windowStart + this.windowMs;
    const key = `${ip}:${windowStart.toString()}`;

    const entry = this.store.get(key);

    if (entry === undefined) {
      // First request in this window
      this.store.set(key, { count: 1, windowStart });
      return {
        allowed: true,
        count: 1,
        limit: this.maxRequests,
        resetAt: Math.floor(resetAt / 1000),
        remaining: this.maxRequests - 1,
      };
    }

    entry.count++;
    const allowed = entry.count <= this.maxRequests;

    return {
      allowed,
      count: entry.count,
      limit: this.maxRequests,
      resetAt: Math.floor(resetAt / 1000),
      remaining: Math.max(0, this.maxRequests - entry.count),
    };
  }

  /**
   * Get the current count for an IP without incrementing.
   */
  public peek(ip: string): number {
    const now = Date.now();
    const windowStart = Math.floor(now / this.windowMs) * this.windowMs;
    const key = `${ip}:${windowStart.toString()}`;
    return this.store.get(key)?.count ?? 0;
  }

  /**
   * Reset the rate limit for a specific IP (e.g., after manual review).
   */
  public reset(ip: string): void {
    const now = Date.now();
    const windowStart = Math.floor(now / this.windowMs) * this.windowMs;
    const key = `${ip}:${windowStart.toString()}`;
    this.store.delete(key);
  }

  /**
   * Get total number of unique IPs currently tracked.
   */
  public get trackedIps(): number {
    return this.store.size;
  }

  /**
   * Clean up expired windows and stop the cleanup timer.
   * Call this when the server shuts down.
   */
  public shutdown(): void {
    if (this.cleanupTimer !== null) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
    this.store.clear();
  }

  // ─── Private ───────────────────────────────────────────────────────────────

  private startCleanup(): void {
    // Purge expired entries every 5 minutes to prevent memory accumulation
    this.cleanupTimer = setInterval(() => {
      this.purgeExpired();
    }, 5 * 60 * 1000);

    if (this.cleanupTimer !== null && 'unref' in this.cleanupTimer) {
      this.cleanupTimer.unref();
    }
  }

  private purgeExpired(): void {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (now - entry.windowStart > this.windowMs * 2) {
        this.store.delete(key);
      }
    }
  }
}

/**
 * Extract the real client IP from an Express request.
 * Handles X-Forwarded-For with configurable trust level.
 *
 * @param req         - Express request object (compatible interface)
 * @param trustHops   - Number of proxy hops to trust. 0 = socket IP only
 */
export function extractClientIp(
  req: {
    ip?: string;
    socket?: { remoteAddress?: string };
    headers: Record<string, string | string[] | undefined>;
  },
  trustHops = 0,
): string {
  if (trustHops > 0) {
    const xff = req.headers['x-forwarded-for'];
    if (xff !== undefined) {
      const ips = (Array.isArray(xff) ? xff.join(',') : xff)
        .split(',')
        .map((ip) => ip.trim())
        .filter(Boolean);

      // The client IP is at position: length - trustHops
      // (rightmost untrusted IP)
      const targetIndex = ips.length - trustHops;
      if (targetIndex >= 0 && targetIndex < ips.length) {
        const ip = ips[targetIndex];
        if (ip !== undefined) { return ip; }
      }
    }
  }

  return req.ip ?? req.socket?.remoteAddress ?? '0.0.0.0';
}

