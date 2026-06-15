/**
 * Unit tests: IP Address Validator
 */

import { checkIpAddress, isBlockedIp } from '../../src/validators/ip-validator';

describe('checkIpAddress — blocked IPs', () => {
  // ── Loopback ──────────────────────────────────────────────────────────────
  describe('Loopback addresses', () => {
    const cases = [
      '127.0.0.1',
      '127.0.0.255',
      '127.255.255.255',
      '127.0.0.0',
    ];

    test.each(cases)('blocks loopback: %s', (ip) => {
      const result = checkIpAddress(ip);
      expect(result.blocked).toBe(true);
      expect(result.threatCategory).toBe('LOOPBACK');
    });
  });

  // ── Private RFC1918 ────────────────────────────────────────────────────────
  describe('RFC1918 private addresses', () => {
    const cases = [
      ['10.0.0.1', 'PRIVATE_IP'],
      ['10.255.255.255', 'PRIVATE_IP'],
      ['172.16.0.1', 'PRIVATE_IP'],
      ['172.31.255.255', 'PRIVATE_IP'],
      ['192.168.0.1', 'PRIVATE_IP'],
      ['192.168.255.255', 'PRIVATE_IP'],
    ];

    test.each(cases)('blocks %s as %s', (ip, category) => {
      const result = checkIpAddress(ip);
      expect(result.blocked).toBe(true);
      expect(result.threatCategory).toBe(category);
    });
  });

  // ── Cloud Metadata ─────────────────────────────────────────────────────────
  describe('Cloud metadata IPs', () => {
    it('blocks AWS IMDS: 169.254.169.254', () => {
      const result = checkIpAddress('169.254.169.254');
      expect(result.blocked).toBe(true);
      expect(result.threatCategory).toBe('CLOUD_METADATA');
    });

    it('blocks Alibaba Cloud metadata: 100.100.100.200', () => {
      const result = checkIpAddress('100.100.100.200');
      expect(result.blocked).toBe(true);
    });
  });

  // ── Encoded IPs ────────────────────────────────────────────────────────────
  describe('Encoded IP bypass attempts', () => {
    it('blocks decimal integer 2130706433 (= 127.0.0.1)', () => {
      const result = checkIpAddress('2130706433');
      expect(result.blocked).toBe(true);
    });

    it('blocks hex 0x7f000001 (= 127.0.0.1)', () => {
      const result = checkIpAddress('0x7f000001');
      expect(result.blocked).toBe(true);
    });

    it('blocks octal 0177.0.0.1 (= 127.0.0.1)', () => {
      const result = checkIpAddress('0177.0.0.1');
      expect(result.blocked).toBe(true);
    });

    it('blocks short-form 127.1 (= 127.0.0.1)', () => {
      const result = checkIpAddress('127.1');
      expect(result.blocked).toBe(true);
    });

    it('marks encoded IPs as wasEncoded=true', () => {
      expect(checkIpAddress('0x7f000001').wasEncoded).toBe(true);
      expect(checkIpAddress('0177.0.0.1').wasEncoded).toBe(true);
      expect(checkIpAddress('2130706433').wasEncoded).toBe(true);
    });
  });

  // ── IPv6 ───────────────────────────────────────────────────────────────────
  describe('IPv6 addresses', () => {
    it('blocks ::1 (IPv6 loopback)', () => {
      const result = checkIpAddress('::1');
      expect(result.blocked).toBe(true);
      expect(result.threatCategory).toBe('LOOPBACK');
    });

    it('blocks [::1] (bracketed IPv6 loopback)', () => {
      const result = checkIpAddress('[::1]');
      expect(result.blocked).toBe(true);
    });

    it('blocks fe80::1 (IPv6 link-local)', () => {
      const result = checkIpAddress('fe80::1');
      expect(result.blocked).toBe(true);
    });

    it('blocks fc00::1 (IPv6 unique local)', () => {
      const result = checkIpAddress('fc00::1');
      expect(result.blocked).toBe(true);
    });
  });
});

describe('checkIpAddress — allowed IPs', () => {
  const safeCases = [
    '8.8.8.8',
    '1.1.1.1',
    '104.18.0.1',
    '151.101.1.1',
    '203.0.114.1',  // outside TEST-NET-3 (203.0.113.0/24)
    '2606:4700:4700::1111', // Cloudflare IPv6 DNS
  ];

  test.each(safeCases)('allows public IP: %s', (ip) => {
    const result = checkIpAddress(ip);
    expect(result.blocked).toBe(false);
  });
});

describe('isBlockedIp convenience function', () => {
  it('returns true for blocked IPs', () => {
    expect(isBlockedIp('127.0.0.1')).toBe(true);
    expect(isBlockedIp('192.168.1.1')).toBe(true);
  });

  it('returns false for public IPs', () => {
    expect(isBlockedIp('8.8.8.8')).toBe(false);
  });
});

