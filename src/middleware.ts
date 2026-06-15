/**
 * ssrf-shield Express Middleware
 * ──────────────────────────────
 * Drop-in Express (4.x/5.x) middleware that protects URL-accepting endpoints
 * from SSRF attacks in a single line of code.
 *
 * Usage (Express):
 * ─────────────────────────────────────────────────────────────────────────────
 *   import { ssrfGuard } from 'ssrf-shield';
 *
 *   // Protect a single route
 *   app.get('/fetch', ssrfGuard(), async (req, res) => {
 *     const safeUrl = req.ssrfGuard?.safeUrl ?? req.query.url;
 *     const data = await fetch(safeUrl);
 *     res.json(await data.json());
 *   });
 *
 *   // Global middleware with Pro features
 *   app.use(ssrfGuard({
 *     proLicense: process.env.SSRF_GUARD_KEY,
 *     allowlist: ['api.myservice.com', '*.internal.corp'],
 *     onBlock: async (event) => {
 *       await alertingService.send(event);
 *     },
 *   }));
 *
 * Non-Express usage (Fastify, raw fetch wrapper, etc.):
 * ─────────────────────────────────────────────────────────────────────────────
 *   import { checkUrl } from 'ssrf-shield';
 *
 *   const result = await checkUrl(userUrl, options);
 *   if (!result.allowed) throw new Error('SSRF blocked');
 *   const response = await fetch(result.safeUrl);
 */

import type { Request, Response, NextFunction, RequestHandler } from 'express';
import { checkUrl } from './guard.js';
import { resolveOptions } from './utils/options-resolver.js';
import type { SsrfGuardOptions } from './types/options.js';
import type { BlockEvent, AllowEvent } from './types/options.js';

// Extend Express Request to include ssrfGuard context
declare module 'express-serve-static-core' {
  interface Request {
    ssrfGuard?: {
      /** The normalized, safe URL. Always use this for downstream requests. */
      safeUrl: string;
      /** Resolved IP addresses from DNS check */
      resolvedIps?: string[];
      /** How long the check took */
      durationMs: number;
    };
  }
}

/**
 * ssrfGuard() — Express middleware factory.
 *
 * Returns an Express middleware that intercepts requests, extracts the URL
 * parameter, validates it against SSRF attack patterns, and either blocks
 * (403) or passes control to the next handler with a sanitized URL.
 *
 * @param options - Configuration options (see SsrfGuardOptions)
 * @returns Express RequestHandler
 */
export function ssrfGuard(options: SsrfGuardOptions = {}): RequestHandler {
  const resolved = resolveOptions(options);

  return ((req: Request, res: Response, next: NextFunction): void => {
    void (async (): Promise<void> => {
    // ── Extract the URL to validate ─────────────────────────────────────────
    const paramName = resolved.urlParam;
    const rawUrl =
      (req.query[paramName] as string | undefined) ??
      (req.body as Record<string, unknown> | undefined)?.[paramName] as string | undefined ??
      (req.params[paramName] as string | undefined);

    // If no URL parameter found in this request, pass through unchanged
    if (rawUrl === undefined || rawUrl === null || rawUrl === '') {
      next();
      return;
    }

    // ── Run the security check ──────────────────────────────────────────────
    const result = await checkUrl(rawUrl, options);

    if (!result.allowed) {
      // ── Blocked — fire onBlock callback and return 403 ─────────────────
      // result.threat is always present when allowed === false
      const threat = result.threat ?? { reason: 'SSRF blocked', category: 'INVALID_URL', severity: 'high' as const, likelyBypassAttempt: false };

      if (resolved.isPro && options.onBlock !== undefined) {
        // Fire-and-forget — don't let logging errors crash the request
        const blockEvt: BlockEvent = {
          ip: req.ip ?? req.socket?.remoteAddress ?? 'unknown',
          url: rawUrl,
          reason: threat.reason,
          threatCategory: threat.category,
          severity: threat.severity,
          likelyBypassAttempt: threat.likelyBypassAttempt,
          timestamp: new Date(),
          requestPath: req.path,
          durationMs: result.durationMs,
        };
        const userAgent = req.headers['user-agent'];
        if (userAgent !== undefined) {
          blockEvt.userAgent = userAgent;
        }
        if (result.resolvedIps !== undefined) {
          blockEvt.resolvedIps = result.resolvedIps;
        }
        Promise.resolve(options.onBlock(blockEvt)).catch(() => {/* swallow */});
      }

      const responseBody: Record<string, unknown> = {
        error: 'SSRF_BLOCKED',
        message: resolved.exposeReason
          ? threat.reason
          : 'Request blocked by ssrf-shield',
        code: threat.category,
      };

      if (resolved.exposeReason) {
        responseBody['severity'] = threat.severity;
        responseBody['likelyBypassAttempt'] = threat.likelyBypassAttempt;
      }

      res.status(resolved.blockedStatusCode).json(responseBody);
      return;
    }

    // ── Allowed — attach clean URL to request for downstream use ──────────
    const ssrfCtx: { safeUrl: string; durationMs: number; resolvedIps?: string[] } = {
      safeUrl: result.safeUrl ?? '',
      durationMs: result.durationMs,
    };
    if (result.resolvedIps !== undefined) {
      ssrfCtx.resolvedIps = result.resolvedIps;
    }
    req.ssrfGuard = ssrfCtx;

    if (resolved.isPro && options.onAllow !== undefined) {
      const allowEvt: AllowEvent = {
        ip: req.ip ?? req.socket?.remoteAddress ?? 'unknown',
        url: result.safeUrl ?? '',
        timestamp: new Date(),
        requestPath: req.path,
        durationMs: result.durationMs,
      };
      if (result.resolvedIps !== undefined) {
        allowEvt.resolvedIps = result.resolvedIps;
      }
      Promise.resolve(options.onAllow(allowEvt)).catch(() => {/* swallow */});
    }

      next();
    })();
  }) as RequestHandler;
}

/**
 * Fastify plugin adapter.
 * Wraps ssrfGuard logic for use with Fastify hooks.
 *
 * Usage:
 *   fastify.addHook('preHandler', ssrfGuardFastify({ urlParam: 'target' }));
 */
export function ssrfGuardFastify(options: SsrfGuardOptions = {}) {
  const resolved = resolveOptions(options);

  return async function fastifyHook(
    request: {
      query: Record<string, unknown>;
      body: Record<string, unknown> | null | undefined;
      params: Record<string, unknown>;
      ip: string;
      url: string;
      headers: Record<string, string | string[] | undefined>;
    },
    reply: {
      code: (n: number) => { send: (data: unknown) => void };
    },
  ): Promise<void> {
    const paramName = resolved.urlParam;
    const bodyParam = request.body?.[paramName];
    const rawUrl =
      (request.query[paramName] as string | undefined) ??
      (typeof bodyParam === 'string' ? bodyParam : undefined) ??
      (request.params[paramName] as string | undefined);

    if (!rawUrl) {
      return;
    }

    const result = await checkUrl(rawUrl, options);
    if (!result.allowed) {
      const threat = result.threat;
      reply.code(resolved.blockedStatusCode).send({
        error: 'SSRF_BLOCKED',
        message: resolved.exposeReason
          ? (threat?.reason ?? 'SSRF blocked')
          : 'Request blocked by ssrf-shield',
        code: threat?.category ?? 'INVALID_URL',
      });
    }
  };
}

// Re-export the core function for non-middleware use cases
export { checkUrl, checkUrlSync } from './guard.js';

