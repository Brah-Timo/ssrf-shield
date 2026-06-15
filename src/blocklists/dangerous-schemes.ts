/**
 * Dangerous URL Schemes / Protocols
 * ────────────────────────────────────
 * SSRF is NOT limited to HTTP. Attackers use alternative protocols to:
 *
 *  file://   → Read arbitrary files from the server's filesystem
 *              e.g. file:///etc/passwd, file:///proc/self/environ
 *
 *  gopher:// → Full TCP request crafting. Can send raw data to ANY port.
 *              Classic Redis attack: gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall
 *              Bypasses most HTTP-based protections.
 *
 *  dict://   → DICT protocol — can enumerate ports and retrieve data
 *              e.g. dict://localhost:6379/CONFIG
 *
 *  ftp://    → FTP bounce attack, internal service enumeration
 *
 *  data://   → Embed arbitrary content inline, can exfiltrate data
 *              or trigger XSS: data:text/html,<script>alert(1)</script>
 *
 *  ldap://   → LDAP injection, internal directory service access
 *
 *  jar://    → Java-specific: can read files from JARs on the filesystem
 *
 *  phar://   → PHP-specific: deserializes PHAR archives → RCE
 *
 * Only http:// and https:// should be allowed for outbound requests.
 */

export class BlockedSchemeError extends Error {
  public readonly code = 'BLOCKED_SCHEME' as const;
  public readonly scheme: string;

  public constructor(scheme: string) {
    super(
      `Protocol "${scheme}" is blocked. Only HTTP and HTTPS are permitted for outbound requests.`,
    );
    this.name = 'BlockedSchemeError';
    this.scheme = scheme;
  }
}

/**
 * Exhaustive set of non-HTTP(S) schemes that MUST be blocked.
 * Kept as Set<string> for O(1) lookup performance.
 */
export const DANGEROUS_SCHEMES: ReadonlySet<string> = new Set([
  // ── File System Access ────────────────────────────────────────────────────
  'file',       // Local file reads: file:///etc/passwd
  'jar',        // Java Archive reads (JVM apps): jar:file:///app.jar!/
  'phar',       // PHP Archive (RCE via deserialization): phar:///var/www/shell.phar

  // ── Network Protocols (non-HTTP) ──────────────────────────────────────────
  'gopher',     // Raw TCP — the most dangerous: can speak Redis, SMTP, etc.
  'ftp',        // FTP, FTP bounce attack
  'ftps',       // Encrypted FTP
  'sftp',       // SSH File Transfer Protocol
  'tftp',       // Trivial FTP (UDP, common in embedded systems)

  // ── Data / Inline ─────────────────────────────────────────────────────────
  'data',       // Inline data: data:text/html,<script>...
  'blob',       // Binary large object (browser-side usually, still block)

  // ── Scripting ─────────────────────────────────────────────────────────────
  'javascript', // XSS via javascript:alert(1)
  'vbscript',   // Legacy VBScript (IE/Edge-old): vbscript:msgbox(1)

  // ── Directory / Query Protocols ──────────────────────────────────────────
  'dict',       // DICT protocol — port scan & data retrieval
  'ldap',       // LDAP injection, internal directory enumeration
  'ldaps',      // Encrypted LDAP
  'ldapi',      // LDAP over Unix socket

  // ── Messaging / Mail ─────────────────────────────────────────────────────
  'smtp',       // Email relay via SSRF (spam, phishing relay)
  'smtps',      // Encrypted SMTP
  'imap',       // Email retrieval
  'imaps',      // Encrypted IMAP
  'pop3',       // POP3 email
  'pop3s',      // Encrypted POP3

  // ── Network Management ────────────────────────────────────────────────────
  'snmp',       // SNMP — network device enumeration
  'telnet',     // Unencrypted shell access

  // ── News / Usenet ─────────────────────────────────────────────────────────
  'nntp',       // Network News Transfer Protocol
  'news',       // Usenet news

  // ── IRC / Chat ────────────────────────────────────────────────────────────
  'irc',        // Internet Relay Chat (can be used for exfiltration)
  'ircs',       // Encrypted IRC
  'xmpp',       // Jabber/XMPP

  // ── Windows / SMB ─────────────────────────────────────────────────────────
  'smb',        // Windows file shares — internal network traversal
  'cifs',       // Common Internet File System

  // ── Other Dangerous ────────────────────────────────────────────────────────
  'netdoc',     // Java-specific: reads from InputStream
  'about',      // about:blank, about:config — browser-internal
  'chrome',     // Chrome internal pages
  'chrome-extension', // Chrome extensions
  'moz-extension',    // Firefox extensions
  'ms-browser-extension', // Edge extensions
  'resource',   // Firefox internal resources
  'feed',       // RSS/Atom feeds (can access local files in some implementations)
  'cap',        // Content Addressable Protocol
  'ipp',        // Internet Printing Protocol
]) satisfies ReadonlySet<string>;

/**
 * The only permitted schemes for outbound HTTP requests.
 */
export const ALLOWED_SCHEMES: ReadonlySet<string> = new Set(['http', 'https']);

/**
 * Validate the scheme/protocol of a URL.
 * Throws BlockedSchemeError if the scheme is not http or https.
 *
 * @param protocol - URL.protocol value (e.g. "https:", "file:")
 * @throws {BlockedSchemeError}
 */
export function validateScheme(protocol: string): void {
  // URL.protocol includes trailing colon: "https:" → "https"
  const scheme = protocol.replace(/:$/, '').toLowerCase().trim();

  if (!ALLOWED_SCHEMES.has(scheme)) {
    throw new BlockedSchemeError(scheme);
  }
}

/**
 * Check whether a given scheme string is explicitly in the danger list.
 */
export function isDangerousScheme(protocol: string): boolean {
  const scheme = protocol.replace(/:$/, '').toLowerCase().trim();
  return DANGEROUS_SCHEMES.has(scheme);
}

