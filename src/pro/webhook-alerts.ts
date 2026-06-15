/**
 * [PRO] Webhook Alerting System
 * ──────────────────────────────
 * Sends real-time SSRF attack notifications to external systems
 * via HTTP webhooks.
 *
 * Compatible with:
 *  - Slack Incoming Webhooks
 *  - PagerDuty Events API
 *  - Microsoft Teams Connectors
 *  - Discord Webhooks
 *  - Generic HTTP endpoints
 *  - Custom SIEM integrations
 *
 * Security:
 *  - HMAC-SHA256 signature on every request (X-ssrf-shield-Signature header)
 *  - Shared secret for verification on the receiving end
 *  - Replay prevention via timestamp + nonce in payload
 *
 * Delivery guarantees:
 *  - Retries with exponential backoff (up to 3 attempts)
 *  - Non-blocking (never delays the HTTP response to the user)
 *  - Rate-limited (max 10 webhooks/sec to prevent flood)
 */

import { createHmac, randomBytes } from 'crypto';
import type { BlockEvent } from '../types/options.js';

export interface WebhookOptions {
  /** Webhook endpoint URL */
  url: string;
  /** HMAC secret for payload signing. Set the same on your receiver. */
  secret?: string;
  /** Minimum severity to trigger a webhook. Default: 'high' */
  minSeverity?: 'critical' | 'high' | 'medium' | 'low';
  /** Custom headers to include in webhook requests */
  customHeaders?: Record<string, string>;
  /** Request timeout in ms. Default: 5000 */
  timeoutMs?: number;
  /** Maximum retries on failure. Default: 3 */
  maxRetries?: number;
  /** Webhook payload format. Default: 'ssrf-shield' */
  format?: 'ssrf-shield' | 'slack' | 'pagerduty' | 'discord';
}

export interface WebhookPayload {
  /** Payload version for forward compatibility */
  version: '1.0';
  /** Event type */
  event: 'ssrf.blocked';
  /** Unique delivery ID */
  deliveryId: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** The block event data */
  data: BlockEvent;
}

const SEVERITY_ORDER: Record<string, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/**
 * Webhook alerter for real-time SSRF attack notifications.
 *
 * Usage:
 *   const alerter = new WebhookAlerter({
 *     url: 'https://hooks.slack.com/services/...',
 *     secret: process.env.WEBHOOK_SECRET,
 *     minSeverity: 'high',
 *     format: 'slack',
 *   });
 *
 *   app.use(ssrfGuard({
 *     proLicense: process.env.SSRF_GUARD_KEY,
 *     onBlock: (event) => alerter.send(event),
 *   }));
 */
export class WebhookAlerter {
  private readonly options: Required<WebhookOptions>;
  private lastSentAt = 0;
  private readonly minIntervalMs = 100; // 10 webhooks/sec max

  public constructor(options: WebhookOptions) {
    this.options = {
      url: options.url,
      secret: options.secret ?? '',
      minSeverity: options.minSeverity ?? 'high',
      customHeaders: options.customHeaders ?? {},
      timeoutMs: options.timeoutMs ?? 5000,
      maxRetries: options.maxRetries ?? 3,
      format: options.format ?? 'ssrf-shield',
    };
  }

  /**
   * Send a webhook for a block event.
   * Non-blocking — fire and forget.
   *
   * @param event - The BlockEvent to send
   */
  public send(event: BlockEvent): void {
    // Check minimum severity filter
    const eventSeverityLevel = SEVERITY_ORDER[event.severity] ?? 0;
    const minSeverityLevel = SEVERITY_ORDER[this.options.minSeverity] ?? 2;

    if (eventSeverityLevel < minSeverityLevel) {
      return; // Below threshold, skip
    }

    // Throttle if sending too fast
    const now = Date.now();
    const delay = Math.max(0, this.minIntervalMs - (now - this.lastSentAt));
    this.lastSentAt = now + delay;

    setTimeout(() => {
      this.sendWithRetry(event).catch(() => {/* swallow */});
    }, delay);
  }

  /**
   * Send a webhook and wait for delivery confirmation.
   * Useful for critical alerts that must not be lost.
   */
  public async sendSync(event: BlockEvent): Promise<void> {
    await this.sendWithRetry(event);
  }

  // ─── Private ───────────────────────────────────────────────────────────────

  private async sendWithRetry(event: BlockEvent, attempt = 1): Promise<void> {
    try {
      await this.deliver(event);
    } catch {
      if (attempt < this.options.maxRetries) {
        const delay = Math.pow(2, attempt - 1) * 1000;
        await sleep(delay);
        await this.sendWithRetry(event, attempt + 1);
      }
      // All retries failed — fail silently (never crash the app)
    }
  }

  private async deliver(event: BlockEvent): Promise<void> {
    const deliveryId = randomBytes(16).toString('hex');
    const timestamp = new Date().toISOString();
    const body = this.buildPayload(event, deliveryId, timestamp);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs);

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'User-Agent': 'ssrf-shield/1.0.0 (webhook)',
        'X-ssrf-shield-Delivery': deliveryId,
        'X-ssrf-shield-Event': 'ssrf.blocked',
        ...this.options.customHeaders,
      };

      // Add HMAC signature if secret is configured
      if (this.options.secret.length > 0) {
        const signature = this.sign(body);
        headers['X-ssrf-shield-Signature'] = `sha256=${signature}`;
      }

      const response = await fetch(this.options.url, {
        method: 'POST',
        headers,
        body,
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Webhook returned HTTP ${response.status.toString()}`);
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  private buildPayload(
    event: BlockEvent,
    deliveryId: string,
    timestamp: string,
  ): string {
    switch (this.options.format) {
      case 'slack':
        return JSON.stringify(this.buildSlackPayload(event));

      case 'pagerduty':
        return JSON.stringify(this.buildPagerDutyPayload(event, deliveryId));

      case 'discord':
        return JSON.stringify(this.buildDiscordPayload(event));

      case 'ssrf-shield':
      default:
        return JSON.stringify({
          version: '1.0',
          event: 'ssrf.blocked',
          deliveryId,
          timestamp,
          data: event,
        } satisfies WebhookPayload);
    }
  }

  private sign(body: string): string {
    return createHmac('sha256', this.options.secret)
      .update(body, 'utf8')
      .digest('hex');
  }

  private buildSlackPayload(event: BlockEvent): Record<string, unknown> {
    const severityEmoji: Record<string, string> = {
      critical: '🚨',
      high: '⚠️',
      medium: '⚡',
      low: '🔍',
    };
    const emoji = severityEmoji[event.severity] ?? '⚠️';

    return {
      text: `${emoji} *SSRF Attack Blocked* [${event.severity.toUpperCase()}]`,
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: `${emoji} SSRF Attack Blocked`,
          },
        },
        {
          type: 'section',
          fields: [
            { type: 'mrkdwn', text: `*Threat:*\n${event.threatCategory}` },
            { type: 'mrkdwn', text: `*Severity:*\n${event.severity.toUpperCase()}` },
            { type: 'mrkdwn', text: `*Blocked URL:*\n\`${event.url}\`` },
            { type: 'mrkdwn', text: `*Source IP:*\n${event.ip}` },
            { type: 'mrkdwn', text: `*Reason:*\n${event.reason}` },
            { type: 'mrkdwn', text: `*Bypass Attempt:*\n${event.likelyBypassAttempt ? 'Yes' : 'No'}` },
          ],
        },
        {
          type: 'context',
          elements: [
            {
              type: 'mrkdwn',
              text: `Path: ${event.requestPath} | Time: ${event.timestamp.toISOString()} | Duration: ${event.durationMs.toString()}ms`,
            },
          ],
        },
      ],
    };
  }

  private buildPagerDutyPayload(
    event: BlockEvent,
    dedupKey: string,
  ): Record<string, unknown> {
    const pdSeverity: Record<string, string> = {
      critical: 'critical',
      high: 'error',
      medium: 'warning',
      low: 'info',
    };

    return {
      routing_key: this.options.secret,
      dedup_key: dedupKey,
      event_action: 'trigger',
      payload: {
        summary: `SSRF blocked: ${event.threatCategory} from ${event.ip}`,
        severity: pdSeverity[event.severity] ?? 'warning',
        source: event.ip,
        timestamp: event.timestamp.toISOString(),
        custom_details: {
          url: event.url,
          reason: event.reason,
          path: event.requestPath,
          bypass_attempt: event.likelyBypassAttempt,
        },
      },
    };
  }

  private buildDiscordPayload(event: BlockEvent): Record<string, unknown> {
    const colors: Record<string, number> = {
      critical: 0xff0000,
      high: 0xff6600,
      medium: 0xffcc00,
      low: 0x0099ff,
    };

    return {
      embeds: [
        {
          title: '🛡️ SSRF Attack Blocked',
          color: colors[event.severity] ?? 0xff6600,
          fields: [
            { name: 'Threat Category', value: event.threatCategory, inline: true },
            { name: 'Severity', value: event.severity.toUpperCase(), inline: true },
            { name: 'Source IP', value: event.ip, inline: true },
            { name: 'Blocked URL', value: `\`${event.url}\``, inline: false },
            { name: 'Reason', value: event.reason, inline: false },
          ],
          footer: { text: `ssrf-shield | ${event.timestamp.toISOString()}` },
        },
      ],
    };
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

