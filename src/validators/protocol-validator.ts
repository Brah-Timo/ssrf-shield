/**
 * Protocol Validator
 * ───────────────────
 * Validates URL protocols and port assignments.
 * Enforces the principle of least privilege — only allow what is explicitly needed.
 *
 * Responsibilities:
 *  1. Validate that the scheme is HTTP or HTTPS only
 *  2. Check that the port number is not a known internal service port
 *  3. Detect port-scheme mismatches (e.g., HTTP on port 443 is suspicious)
 */

import { validateScheme, BlockedSchemeError } from '../blocklists/dangerous-schemes.js';
import type { ThreatCategory } from '../types/threat.js';
import { DEFAULT_BLOCKED_PORTS } from '../types/options.js';

export interface ProtocolValidationResult {
  valid: boolean;
  reason?: string;
  threatCategory?: ThreatCategory;
}

/**
 * Validate the URL protocol/scheme.
 *
 * @param protocol - URL.protocol value (e.g. "https:")
 * @returns validation result
 */
export function validateProtocol(protocol: string): ProtocolValidationResult {
  try {
    validateScheme(protocol);
    return { valid: true };
  } catch (err) {
    if (err instanceof BlockedSchemeError) {
      return {
        valid: false,
        reason: err.message,
        threatCategory: 'BLOCKED_SCHEME',
      };
    }
    return {
      valid: false,
      reason: `Unknown protocol error: ${String(err)}`,
      threatCategory: 'BLOCKED_SCHEME',
    };
  }
}

/**
 * Validate the port number of a URL.
 *
 * @param port           - Effective port number (already resolved from URL)
 * @param blockedPorts   - Set of blocked port numbers (merged from defaults + user config)
 * @returns validation result
 */
export function validatePort(
  port: number,
  blockedPorts: ReadonlySet<number> | readonly number[],
): ProtocolValidationResult {
  const portsSet =
    blockedPorts instanceof Set
      ? blockedPorts
      : new Set(blockedPorts);

  if (portsSet.has(port)) {
    const serviceName = getServiceName(port);
    return {
      valid: false,
      reason: serviceName
        ? `Port ${port} is blocked (${serviceName} — internal service port)`
        : `Port ${port} is blocked (internal service port)`,
      threatCategory: 'BLOCKED_PORT',
    };
  }

  return { valid: true };
}

/**
 * Build the effective blocked ports set by merging defaults with user config.
 */
export function buildBlockedPortsSet(
  userPorts?: number[],
  additionalPorts?: number[],
): Set<number> {
  if (userPorts !== undefined) {
    // User explicitly overrides the entire list
    const s = new Set(userPorts);
    if (additionalPorts !== undefined) {
      for (const p of additionalPorts) {
        s.add(p);
      }
    }
    return s;
  }

  // Merge defaults with any additional user-specified ports
  const s = new Set<number>(DEFAULT_BLOCKED_PORTS);
  if (additionalPorts !== undefined) {
    for (const p of additionalPorts) {
      s.add(p);
    }
  }
  return s;
}

/**
 * Return the well-known service name for a port number, if any.
 */
export function getServiceName(port: number): string | undefined {
  const WELL_KNOWN: Record<number, string> = {
    21:    'FTP',
    22:    'SSH',
    23:    'Telnet',
    25:    'SMTP',
    53:    'DNS',
    110:   'POP3',
    143:   'IMAP',
    389:   'LDAP',
    445:   'SMB',
    636:   'LDAPS',
    1433:  'SQL Server',
    1521:  'Oracle DB',
    2049:  'NFS',
    2181:  'ZooKeeper',
    2375:  'Docker API',
    2376:  'Docker API (TLS)',
    2379:  'etcd',
    2380:  'etcd peer',
    3306:  'MySQL/MariaDB',
    3389:  'RDP',
    4001:  'etcd legacy',
    5432:  'PostgreSQL',
    5672:  'RabbitMQ',
    5900:  'VNC',
    5984:  'CouchDB',
    6379:  'Redis',
    6380:  'Redis TLS',
    7001:  'WebLogic',
    8086:  'InfluxDB',
    8500:  'Consul',
    8888:  'Jupyter Notebook',
    9042:  'Cassandra',
    9090:  'Prometheus',
    9092:  'Kafka',
    9200:  'Elasticsearch',
    9300:  'Elasticsearch transport',
    10250: 'Kubernetes Kubelet',
    11211: 'Memcached',
    15672: 'RabbitMQ Management',
    27017: 'MongoDB',
    27018: 'MongoDB shard',
    27019: 'MongoDB config',
    50070: 'Hadoop NameNode',
    61616: 'ActiveMQ',
  };
  return WELL_KNOWN[port];
}

