/**
 * Cloud Metadata Endpoints
 * ─────────────────────────
 * Explicit block-list for known cloud provider metadata endpoints.
 * These are the most high-value SSRF targets because they expose:
 *  - IAM credentials (AWS)
 *  - Service account tokens (GCP)
 *  - Managed identity tokens (Azure)
 *  - Instance metadata (all providers)
 *
 * AWS Capital One breach (2019): attacker used SSRF to reach IMDS
 * at 169.254.169.254 and stole IAM role credentials.
 *
 * Even though 169.254.0.0/16 is already blocked by private-ranges,
 * we keep this explicit list for:
 *  1. Clear error messages ("Cloud metadata blocked" vs generic)
 *  2. Hostname-based blocking (metadata.google.internal)
 *  3. Future providers not covered by IP ranges
 */

export interface CloudMetadataEndpoint {
  /** IP address or hostname */
  host: string;
  /** Cloud provider name */
  provider: string;
  /** What this endpoint exposes */
  description: string;
  /** Severity: 'critical' = exposes credentials */
  severity: 'critical' | 'high' | 'medium';
}

export const CLOUD_METADATA_ENDPOINTS: readonly CloudMetadataEndpoint[] = [
  // ── Amazon Web Services (AWS) ─────────────────────────────────────────────
  {
    host: '169.254.169.254',
    provider: 'AWS',
    description: 'AWS Instance Metadata Service (IMDSv1/v2). Exposes IAM role credentials.',
    severity: 'critical',
  },
  {
    host: '169.254.170.2',
    provider: 'AWS',
    description: 'AWS ECS Task Metadata endpoint. Exposes task credentials.',
    severity: 'critical',
  },
  {
    host: 'fd00:ec2::254',
    provider: 'AWS',
    description: 'AWS IMDS via IPv6.',
    severity: 'critical',
  },

  // ── Google Cloud Platform (GCP) ───────────────────────────────────────────
  {
    host: '169.254.169.254',
    provider: 'GCP',
    description: 'GCP Instance Metadata Server. Exposes service account tokens.',
    severity: 'critical',
  },
  {
    host: 'metadata.google.internal',
    provider: 'GCP',
    description: 'GCP metadata hostname. Resolves to 169.254.169.254.',
    severity: 'critical',
  },

  // ── Microsoft Azure ───────────────────────────────────────────────────────
  {
    host: '169.254.169.254',
    provider: 'Azure',
    description: 'Azure Instance Metadata Service. Exposes managed identity tokens.',
    severity: 'critical',
  },

  // ── Alibaba Cloud ─────────────────────────────────────────────────────────
  {
    host: '100.100.100.200',
    provider: 'Alibaba',
    description: 'Alibaba Cloud ECS Metadata. Exposes RAM role credentials.',
    severity: 'critical',
  },

  // ── DigitalOcean ─────────────────────────────────────────────────────────
  {
    host: '169.254.169.254',
    provider: 'DigitalOcean',
    description: 'DigitalOcean Metadata Service.',
    severity: 'high',
  },

  // ── Oracle Cloud Infrastructure (OCI) ────────────────────────────────────
  {
    host: '169.254.169.254',
    provider: 'OCI',
    description: 'Oracle Cloud Instance Metadata Service.',
    severity: 'critical',
  },

  // ── IBM Cloud ────────────────────────────────────────────────────────────
  {
    host: '169.254.169.254',
    provider: 'IBM',
    description: 'IBM Cloud Instance Metadata Service.',
    severity: 'critical',
  },

  // ── Kubernetes ───────────────────────────────────────────────────────────
  {
    host: 'kubernetes.default.svc',
    provider: 'Kubernetes',
    description: 'Kubernetes API server (default service account).',
    severity: 'critical',
  },
  {
    host: 'kubernetes.default.svc.cluster.local',
    provider: 'Kubernetes',
    description: 'Kubernetes API server (FQDN).',
    severity: 'critical',
  },
  {
    host: '10.96.0.1',
    provider: 'Kubernetes',
    description: 'Default Kubernetes API server IP (kubeadm default).',
    severity: 'critical',
  },
] as const;

/**
 * Fast lookup Sets for O(1) hostname/IP checks.
 * Populated from CLOUD_METADATA_ENDPOINTS.
 */
export const CLOUD_METADATA_IPS = new Set<string>(
  CLOUD_METADATA_ENDPOINTS
    .filter((e) => /^[\d.:[\]]+$/.test(e.host))  // IP addresses only
    .map((e) => e.host.toLowerCase()),
);

export const CLOUD_METADATA_HOSTNAMES = new Set<string>(
  CLOUD_METADATA_ENDPOINTS
    .filter((e) => !/^[\d.:[\]]+$/.test(e.host))  // Hostnames only
    .map((e) => e.host.toLowerCase()),
);

/**
 * Get the metadata endpoint info for a given host, or undefined if not found.
 */
export function getCloudMetadataEndpoint(
  host: string,
): CloudMetadataEndpoint | undefined {
  const normalizedHost = host.toLowerCase().replace(/^\[|\]$/g, '');
  return CLOUD_METADATA_ENDPOINTS.find(
    (e) => e.host.toLowerCase() === normalizedHost,
  );
}

/**
 * Check whether a given host (IP or hostname) is a known cloud metadata endpoint.
 */
export function isCloudMetadataHost(host: string): boolean {
  const normalized = host.toLowerCase().replace(/^\[|\]$/g, '');
  return CLOUD_METADATA_IPS.has(normalized) || CLOUD_METADATA_HOSTNAMES.has(normalized);
}

