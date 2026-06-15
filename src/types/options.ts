/**
 * ssrf-shield Configuration Options
 * ──────────────────────────────────
 * Complete type definitions for all configuration options.
 * Supports both free (OSS) and Pro tier features.
 */

import type { ThreatCategory } from './threat.js';

// ─── Core Options (Free Tier) ────────────────────────────────────────────────

export interface SsrfGuardOptions {
  /**
   * Name of the request parameter that carries the URL to be validated.
   *
   * Checked in this order: query string → request body → route params
   *
   * @default 'url'
   * @example 'target', 'endpoint', 'href', 'link'
   */
  urlParam?: string;

  /**
   * List of additional ports to block, merged with the built-in list.
   * The built-in list covers all common internal service ports.
   *
   * Built-in blocked ports:
   *   22 (SSH), 23 (Telnet), 25 (SMTP), 6379 (Redis),
   *   11211 (Memcached), 27017 (MongoDB), 5432 (PostgreSQL),
   *   3306 (MySQL), 9200 (Elasticsearch), 2379 (etcd), 8500 (Consul),
   *   4001 (etcd legacy), 9092 (Kafka), 5672 (RabbitMQ), 6380 (Redis TLS),
   *   3389 (RDP), 5900 (VNC)
   *
   * @default []
   */
  additionalBlockedPorts?: number[];

  /**
   * Override the entire blocked ports list (replaces built-in list entirely).
   * Use this only if you need precise control.
   *
   * @default undefined (uses built-in list)
   */
  blockedPorts?: number[];

  /**
   * DNS resolution timeout in milliseconds.
   * If DNS takes longer, the request is blocked (fail-safe behavior).
   *
   * @default 3000
   */
  dnsTimeoutMs?: number;

  /**
   * Whether to allow the request when DNS resolution fails with an error.
   *
   * - false (default): Fail-safe — block on DNS error (recommended for security)
   * - true: Fail-open — allow when DNS is unavailable (better availability)
   *
   * @default false
   */
  allowOnDnsError?: boolean;

  /**
   * Whether to expose the block reason in the HTTP response body.
   *
   * WARNING: Setting this to true in production may give attackers
   * information about your network topology and what IPs/services exist.
   *
   * @default false
   */
  exposeReason?: boolean;

  /**
   * Custom HTTP status code for blocked requests.
   *
   * @default 403
   */
  blockedStatusCode?: number;

  /**
   * Whether to skip DNS resolution entirely and only validate
   * direct IP addresses. Useful when you control all input URLs
   * and they are always IP-based.
   *
   * NOTE: This leaves you vulnerable to DNS rebinding if URLs use hostnames.
   *
   * @default false
   */
  skipDnsResolution?: boolean;

  /**
   * Whether to perform a second DNS check after following the first redirect.
   * Protects against DNS rebinding attacks more aggressively.
   *
   * @default false
   */
  enableDnsRebindingProtection?: boolean;

  // ── Pro Tier Options ────────────────────────────────────────────────────────

  /**
   * [PRO] Your ssrf-shield Pro license key.
   * Unlocks: allowlist, onBlock/onAllow callbacks, request logging dashboard.
   *
   * Get your key at: https://ssrf-shield.io/pro
   */
  proLicense?: string;

  /**
   * [PRO] List of hostnames or IP addresses that are always allowed,
   * bypassing all SSRF checks. Use for trusted internal services.
   *
   * Supports:
   *  - Exact hostname: 'api.myservice.com'
   *  - Wildcard subdomain: '*.myservice.com' (matches a.myservice.com)
   *  - Exact IP: '10.0.1.5'
   *  - CIDR range: '10.0.0.0/8'
   *
   * @example ['api.myservice.com', '*.internal.corp', '10.0.1.0/24']
   */
  allowlist?: string[];

  /**
   * [PRO] Callback invoked every time a request is BLOCKED.
   * Use for custom logging, metrics, alerting, or audit trails.
   *
   * Called after the response is sent — async errors are swallowed
   * to avoid crashing your application.
   */
  onBlock?: (event: BlockEvent) => Promise<void> | void;

  /**
   * [PRO] Callback invoked every time a request is ALLOWED.
   * Use for audit trails or traffic analysis.
   */
  onAllow?: (event: AllowEvent) => Promise<void> | void;

  /**
   * [PRO] Rate limiting — max requests per minute per source IP.
   * Requests exceeding the limit are blocked with 429 Too Many Requests.
   *
   * @default undefined (no rate limiting)
   */
  rateLimit?: RateLimitOptions;

  /**
   * [PRO] Webhook URL to receive real-time SSRF attack notifications.
   * Sends a POST request with BlockEvent payload.
   *
   * @example 'https://hooks.slack.com/services/...'
   */
  webhookUrl?: string;

  /**
   * [PRO] Webhook secret for HMAC-SHA256 signature verification.
   * The signature is sent in X-ssrf-shield-Signature header.
   */
  webhookSecret?: string;
}

// ─── Event Types ─────────────────────────────────────────────────────────────

export interface BlockEvent {
  /** Source IP address of the request */
  ip: string;
  /** The raw URL that was blocked */
  url: string;
  /** Human-readable block reason */
  reason: string;
  /** Machine-readable threat category */
  threatCategory: ThreatCategory;
  /** Threat severity */
  severity: 'critical' | 'high' | 'medium' | 'low';
  /** Whether this looks like an intentional bypass attempt */
  likelyBypassAttempt: boolean;
  /** When the block occurred */
  timestamp: Date;
  /** The request path (e.g. /api/fetch) */
  requestPath: string;
  /** User-Agent header */
  userAgent?: string;
  /** Resolved IPs from DNS (if DNS was performed) */
  resolvedIps?: string[];
  /** Time taken for the check */
  durationMs: number;
}

export interface AllowEvent {
  /** Source IP address of the request */
  ip: string;
  /** The normalized (safe) URL that was allowed */
  url: string;
  /** When the request was allowed */
  timestamp: Date;
  /** The request path */
  requestPath: string;
  /** Time taken for the check */
  durationMs: number;
  /** Resolved IPs from DNS (if DNS was performed) */
  resolvedIps?: string[];
}

// ─── Rate Limiting ────────────────────────────────────────────────────────────

export interface RateLimitOptions {
  /**
   * Maximum number of requests per window per IP.
   * @default 100
   */
  maxRequests: number;
  /**
   * Time window in seconds.
   * @default 60
   */
  windowSecs: number;
  /**
   * HTTP status code for rate-limited requests.
   * @default 429
   */
  statusCode?: number;
}

// ─── Internal resolved options (with defaults applied) ───────────────────────

export interface ResolvedOptions extends Required<
  Pick<
    SsrfGuardOptions,
    | 'urlParam'
    | 'dnsTimeoutMs'
    | 'allowOnDnsError'
    | 'exposeReason'
    | 'blockedStatusCode'
    | 'skipDnsResolution'
    | 'enableDnsRebindingProtection'
  >
> {
  effectiveBlockedPorts: Set<number>;
  allowlistPatterns: AllowlistPattern[];
  isPro: boolean;
  raw: SsrfGuardOptions;
}

export interface AllowlistPattern {
  type: 'exact-hostname' | 'wildcard-hostname' | 'exact-ip' | 'cidr';
  value: string;
}

/**
 * Default blocked ports — covers all common internal/database service ports.
 */
export const DEFAULT_BLOCKED_PORTS: readonly number[] = [
  22,    // SSH
  23,    // Telnet
  25,    // SMTP
  53,    // DNS (TCP)
  110,   // POP3
  143,   // IMAP
  389,   // LDAP
  445,   // SMB
  636,   // LDAPS
  1433,  // SQL Server
  1521,  // Oracle DB
  2049,  // NFS
  2181,  // ZooKeeper
  2375,  // Docker API (unauthenticated)
  2376,  // Docker API (TLS)
  2379,  // etcd
  2380,  // etcd (peer)
  3000,  // Various dev servers
  3306,  // MySQL / MariaDB
  3389,  // RDP
  4001,  // etcd legacy
  4200,  // Angular dev server
  4444,  // Metasploit
  5000,  // Various dev servers
  5432,  // PostgreSQL
  5672,  // RabbitMQ AMQP
  5900,  // VNC
  5984,  // CouchDB
  6379,  // Redis ← most common SSRF target
  6380,  // Redis TLS
  7001,  // WebLogic / Cassandra
  7002,  // WebLogic SSL
  8020,  // Hadoop NameNode
  8080,  // HTTP alt / Tomcat
  8086,  // InfluxDB
  8088,  // Hadoop / InfluxDB
  8443,  // HTTPS alt
  8500,  // Consul
  8600,  // Consul DNS
  8888,  // Jupyter Notebook
  9000,  // SonarQube / various
  9042,  // Cassandra CQL
  9090,  // Prometheus
  9092,  // Kafka
  9200,  // Elasticsearch HTTP
  9300,  // Elasticsearch transport
  10250, // Kubernetes Kubelet API
  11211, // Memcached
  15672, // RabbitMQ Management UI
  27017, // MongoDB
  27018, // MongoDB shard
  27019, // MongoDB config server
  50070, // Hadoop NameNode WebUI
  61616, // ActiveMQ
] as const;

