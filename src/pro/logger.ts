/**
 * [PRO] Security Event Logger
 * ────────────────────────────
 * Batches and ships security events (blocks + allows) to the
 * ssrf-shield Pro dashboard for visualization and analytics.
 *
 * Features:
 *  - Automatic batching (up to 50 events per flush)
 *  - Auto-flush every 5 seconds
 *  - Retry on network failure with exponential backoff
 *  - Graceful shutdown (flushes on process exit)
 *  - Zero impact on application if logging fails (errors swallowed)
 *
 * Dashboard shows:
 *  - Real-time attack map (geographic distribution)
 *  - Threat category breakdown (pie chart)
 *  - Top attacking IPs
 *  - Timeline of blocked requests
 *  - Severity distribution
 *  - Bypass attempt detection rate
 */

import type { BlockEvent, AllowEvent } from '../types/options.js';

export interface LoggerOptions {
  /** Pro license key for authentication */
  licenseKey: string;
  /** How often to flush the buffer (ms). Default: 5000 */
  flushIntervalMs?: number;
  /** Maximum events to buffer before forcing a flush. Default: 50 */
  maxBufferSize?: number;
  /** API endpoint. Default: https://api.ssrf-shield.io */
  apiEndpoint?: string;
  /** Whether to also log to console. Default: false */
  consoleLog?: boolean;
  /** Max retry attempts on flush failure. Default: 3 */
  maxRetries?: number;
}

export type SecurityEvent =
  | { type: 'block'; data: BlockEvent }
  | { type: 'allow'; data: AllowEvent };

/**
 * Structured logger for ssrf-shield Pro security events.
 *
 * Usage:
 *   const logger = new SsrfGuardLogger({ licenseKey: process.env.SSRF_GUARD_KEY });
 *
 *   app.use(ssrfGuard({
 *     proLicense: process.env.SSRF_GUARD_KEY,
 *     onBlock: (event) => logger.logBlock(event),
 *     onAllow: (event) => logger.logAllow(event),
 *   }));
 *
 *   // On process shutdown:
 *   process.on('SIGTERM', async () => {
 *     await logger.shutdown();
 *   });
 */
export class SsrfGuardLogger {
  private buffer: SecurityEvent[] = [];
  private readonly options: Required<LoggerOptions>;
  private flushTimer: ReturnType<typeof setInterval> | null = null;
  private isShuttingDown = false;
  private pendingFlushes = 0;

  public constructor(options: LoggerOptions) {
    this.options = {
      licenseKey: options.licenseKey,
      flushIntervalMs: options.flushIntervalMs ?? 5000,
      maxBufferSize: options.maxBufferSize ?? 50,
      apiEndpoint: options.apiEndpoint ?? 'https://api.ssrf-shield.io',
      consoleLog: options.consoleLog ?? false,
      maxRetries: options.maxRetries ?? 3,
    };

    this.startAutoFlush();
    this.registerShutdownHandler();
  }

  /**
   * Log a blocked SSRF attempt.
   */
  public logBlock(event: BlockEvent): void {
    if (this.options.consoleLog) {
      const severity = event.severity.toUpperCase();
      console.warn(
        `[ssrf-shield] BLOCKED [${severity}] ${event.threatCategory}: ${event.url} from ${event.ip}`,
      );
    }

    this.buffer.push({ type: 'block', data: event });
    this.maybeFlush();
  }

  /**
   * Log an allowed request (for audit trail).
   */
  public logAllow(event: AllowEvent): void {
    if (this.options.consoleLog) {
      console.debug(`[ssrf-shield] ALLOWED: ${event.url} from ${event.ip}`);
    }
    this.buffer.push({ type: 'allow', data: event });
    this.maybeFlush();
  }

  /**
   * Manually flush the buffer immediately.
   * Resolves when the flush completes (or fails gracefully).
   */
  public async flush(): Promise<void> {
    if (this.buffer.length === 0) {
      return;
    }

    // Snapshot the current buffer and clear it
    const events = [...this.buffer];
    this.buffer = [];

    await this.sendWithRetry(events);
  }

  /**
   * Gracefully shut down the logger.
   * Stops the auto-flush timer and flushes any remaining events.
   */
  public async shutdown(): Promise<void> {
    this.isShuttingDown = true;
    if (this.flushTimer !== null) {
      clearInterval(this.flushTimer);
      this.flushTimer = null;
    }
    await this.flush();
  }

  /**
   * Get current buffer size (for monitoring).
   */
  public get bufferSize(): number {
    return this.buffer.length;
  }

  // ─── Private ───────────────────────────────────────────────────────────────

  private startAutoFlush(): void {
    this.flushTimer = setInterval(() => {
      if (!this.isShuttingDown && this.buffer.length > 0) {
        this.flush().catch(() => {/* errors are handled in sendWithRetry */});
      }
    }, this.options.flushIntervalMs);

    // Allow Node.js to exit without waiting for the timer
    if (this.flushTimer !== null && 'unref' in this.flushTimer) {
      this.flushTimer.unref();
    }
  }

  private maybeFlush(): void {
    if (this.buffer.length >= this.options.maxBufferSize) {
      this.flush().catch(() => {/* swallow */});
    }
  }

  private registerShutdownHandler(): void {
    const handler = (): void => {
      this.shutdown().catch(() => {/* swallow */});
    };
    process.once('exit', handler);
    process.once('SIGTERM', handler);
    process.once('SIGINT', handler);
  }

  private async sendWithRetry(
    events: SecurityEvent[],
    attempt = 1,
  ): Promise<void> {
    try {
      this.pendingFlushes++;
      await this.sendEvents(events);
    } catch (err) {
      if (attempt < this.options.maxRetries) {
        // Exponential backoff: 1s, 2s, 4s
        const delay = Math.pow(2, attempt - 1) * 1000;
        await sleep(delay);
        await this.sendWithRetry(events, attempt + 1);
      } else {
        // All retries failed — put events back at the front of the buffer
        // so we don't lose them permanently
        this.buffer.unshift(...events.slice(0, this.options.maxBufferSize - this.buffer.length));
      }
    } finally {
      this.pendingFlushes--;
    }
  }

  private async sendEvents(events: SecurityEvent[]): Promise<void> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    try {
      const response = await fetch(
        `${this.options.apiEndpoint}/v1/events`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.options.licenseKey}`,
            'User-Agent': 'ssrf-shield/1.0.0',
            'X-Event-Count': events.length.toString(),
          },
          body: JSON.stringify({
            events,
            sentAt: new Date().toISOString(),
          }),
          signal: controller.signal,
        },
      );

      if (!response.ok && response.status !== 202) {
        throw new Error(`Logger API returned ${response.status.toString()}`);
      }
    } finally {
      clearTimeout(timeout);
    }
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

