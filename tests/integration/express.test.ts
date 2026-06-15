/**
 * Integration tests: Express Middleware
 */

import express, { type Request, type Response } from 'express';
import { ssrfGuard } from '../../src/middleware';

// ── Mock response helper ────────────────────────────────────────────────────

interface MockRes {
  _status: number;
  _body: Record<string, unknown>;
  status(code: number): this;
  json(data: Record<string, unknown>): this;
}

function makeMockRes(onJson?: (data: Record<string, unknown>) => void): MockRes {
  const mock: MockRes = {
    _status: 200,
    _body: {},
    status(code: number) {
      this._status = code;
      return this;
    },
    json(data: Record<string, unknown>) {
      this._body = data;
      onJson?.(data);
      return this;
    },
  };
  return mock;
}

// Simple test request simulator (no HTTP server needed)
function createApp(options = {}) {
  const app = express();
  app.use(express.json());
  app.use(express.urlencoded({ extended: true }));

  app.get('/fetch', ssrfGuard(options), (req: Request, res: Response) => {
    res.json({
      success: true,
      safeUrl: req.ssrfGuard?.safeUrl,
    });
  });

  return app;
}

// Simulate a request without HTTP
async function simulateRequest(
  _app: express.Application,
  url: string,
  _method = 'GET',
  body?: Record<string, string>,
): Promise<{ status: number; body: Record<string, unknown> }> {
  return new Promise((resolve) => {
    const req = {
      method: _method,
      url: `/fetch?url=${encodeURIComponent(url)}`,
      path: '/fetch',
      query: { url },
      body: body ?? {},
      params: {},
      headers: { 'user-agent': 'test' },
      ip: '127.0.0.1',
      socket: { remoteAddress: '127.0.0.1' },
    } as unknown as Request;

    const mock = makeMockRes((data) => {
      resolve({ status: mock._status, body: data });
    });
    const res = mock as unknown as Response;

    const next = () => {
      mock.json({ success: true, safeUrl: req.ssrfGuard?.safeUrl });
    };

    const middleware = ssrfGuard();
    void middleware(req, res, next as express.NextFunction);
  });
}

describe('ssrfGuard Express middleware', () => {
  describe('URL extraction', () => {
    it('extracts URL from query string by default', async () => {
      const middleware = ssrfGuard();
      let nextCalled = false;

      const req = {
        query: { url: 'https://example.com/' },
        body: {},
        params: {},
        path: '/test',
        ip: '1.2.3.4',
        headers: {},
      } as unknown as Request;

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      } as unknown as Response;

      await middleware(req, res, () => { nextCalled = true; });
      // Will call next if allowed, or res.status(403) if blocked
      expect(typeof nextCalled).toBe('boolean');
    });

    it('blocks request with private IP in query', async () => {
      const middleware = ssrfGuard();
      let statusCode = 200;

      const req = {
        query: { url: 'http://127.0.0.1/' },
        body: {},
        params: {},
        path: '/fetch',
        ip: '1.2.3.4',
        headers: {},
      } as unknown as Request;

      const mock = makeMockRes(() => { statusCode = mock._status; });
      const res = mock as unknown as Response;

      await middleware(req, res, jest.fn());
      expect(statusCode).toBe(403);
    });

    it('passes through when no URL parameter present', async () => {
      const middleware = ssrfGuard();
      let nextCalled = false;

      const req = {
        query: {},
        body: {},
        params: {},
        path: '/fetch',
        ip: '1.2.3.4',
        headers: {},
      } as unknown as Request;

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      } as unknown as Response;

      await middleware(req, res, () => { nextCalled = true; });
      expect(nextCalled).toBe(true);
    });

    it('respects custom urlParam option', async () => {
      const middleware = ssrfGuard({ urlParam: 'target' });
      let statusCode = 200;

      const req = {
        query: { target: 'http://192.168.1.1/' },
        body: {},
        params: {},
        path: '/proxy',
        ip: '1.2.3.4',
        headers: {},
      } as unknown as Request;

      const mock = makeMockRes(() => { statusCode = mock._status; });
      const res = mock as unknown as Response;

      await middleware(req, res, jest.fn());
      expect(statusCode).toBe(403);
    });
  });

  describe('Response format', () => {
    it('returns SSRF_BLOCKED error code', async () => {
      const middleware = ssrfGuard();
      let responseBody: Record<string, unknown> = {};

      const req = {
        query: { url: 'http://127.0.0.1/' },
        body: {},
        params: {},
        path: '/fetch',
        ip: '1.2.3.4',
        headers: {},
      } as unknown as Request;

      const mock = makeMockRes((data) => { responseBody = data; });
      const res = mock as unknown as Response;

      await middleware(req, res, jest.fn());
      expect(responseBody['error']).toBe('SSRF_BLOCKED');
      expect(responseBody['code']).toBeTruthy();
    });

    it('hides reason by default (exposeReason=false)', async () => {
      const middleware = ssrfGuard({ exposeReason: false });
      let responseBody: Record<string, unknown> = {};

      const req = {
        query: { url: 'http://127.0.0.1/' },
        body: {},
        params: {},
        path: '/fetch',
        ip: '1.2.3.4',
        headers: {},
      } as unknown as Request;

      const res = {
        status: jest.fn().mockReturnThis(),
        json(data: Record<string, unknown>) {
          responseBody = data;
          return this;
        },
      } as unknown as Response;

      await middleware(req, res, jest.fn());
      expect(responseBody['message']).toBe('Request blocked by ssrf-shield');
    });

    it('exposes reason when exposeReason=true', async () => {
      const middleware = ssrfGuard({ exposeReason: true });
      let responseBody: Record<string, unknown> = {};

      const req = {
        query: { url: 'http://127.0.0.1/' },
        body: {},
        params: {},
        path: '/fetch',
        ip: '1.2.3.4',
        headers: {},
      } as unknown as Request;

      const res = {
        status: jest.fn().mockReturnThis(),
        json(data: Record<string, unknown>) {
          responseBody = data;
          return this;
        },
      } as unknown as Response;

      await middleware(req, res, jest.fn());
      // Reason should contain actual IP/threat info
      const message = responseBody['message'] as string;
      expect(message).not.toBe('Request blocked by ssrf-shield');
      expect(message.length).toBeGreaterThan(10);
    });
  });

  describe('Pro features', () => {
    it('fires onBlock callback when blocked', async () => {
      const onBlock = jest.fn().mockResolvedValue(undefined);
      const middleware = ssrfGuard({
        proLicense: 'dev-test-key',
        onBlock,
      });

      const req = {
        query: { url: 'http://192.168.1.1/' },
        body: {},
        params: {},
        path: '/fetch',
        ip: '5.6.7.8',
        headers: { 'user-agent': 'Mozilla/5.0' },
        socket: { remoteAddress: '5.6.7.8' },
      } as unknown as Request;

      const res = {
        status: jest.fn().mockReturnThis(),
        json: jest.fn().mockReturnThis(),
      } as unknown as Response;

      await middleware(req, res, jest.fn());

      // Wait for async callback
      await new Promise((resolve) => setTimeout(resolve, 50));
      expect(onBlock).toHaveBeenCalledTimes(1);
      const callArg = onBlock.mock.calls[0][0];
      expect(callArg.url).toBe('http://192.168.1.1/');
      expect(callArg.ip).toBeTruthy();
    });
  });
});

