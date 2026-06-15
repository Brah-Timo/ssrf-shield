/**
 * Unit tests: CIDR range utilities
 */

import { isInCIDR, isIPv4InCIDR, isIPv6InCIDR, ipv4ToInt, expandIPv6 } from '../../src/utils/cidr';

describe('ipv4ToInt', () => {
  it('converts standard IPv4 addresses', () => {
    expect(ipv4ToInt('127.0.0.1')).toBe(2130706433);
    expect(ipv4ToInt('192.168.1.1')).toBe(3232235777);
    expect(ipv4ToInt('10.0.0.1')).toBe(167772161);
    expect(ipv4ToInt('0.0.0.0')).toBe(0);
    expect(ipv4ToInt('255.255.255.255')).toBe(4294967295);
  });

  it('throws for invalid IPv4', () => {
    expect(() => ipv4ToInt('not.an.ip')).toThrow();
  });
});

describe('isIPv4InCIDR', () => {
  describe('loopback range 127.0.0.0/8', () => {
    it('matches 127.0.0.1', () => expect(isIPv4InCIDR('127.0.0.1', '127.0.0.0/8')).toBe(true));
    it('matches 127.255.255.255', () => expect(isIPv4InCIDR('127.255.255.255', '127.0.0.0/8')).toBe(true));
    it('matches 127.0.0.0', () => expect(isIPv4InCIDR('127.0.0.0', '127.0.0.0/8')).toBe(true));
    it('does not match 128.0.0.1', () => expect(isIPv4InCIDR('128.0.0.1', '127.0.0.0/8')).toBe(false));
  });

  describe('RFC1918 ranges', () => {
    it('10.0.0.0/8 matches 10.0.0.1', () => expect(isIPv4InCIDR('10.0.0.1', '10.0.0.0/8')).toBe(true));
    it('10.0.0.0/8 matches 10.255.255.255', () => expect(isIPv4InCIDR('10.255.255.255', '10.0.0.0/8')).toBe(true));
    it('10.0.0.0/8 does not match 11.0.0.1', () => expect(isIPv4InCIDR('11.0.0.1', '10.0.0.0/8')).toBe(false));
    it('172.16.0.0/12 matches 172.16.0.1', () => expect(isIPv4InCIDR('172.16.0.1', '172.16.0.0/12')).toBe(true));
    it('172.16.0.0/12 matches 172.31.255.255', () => expect(isIPv4InCIDR('172.31.255.255', '172.16.0.0/12')).toBe(true));
    it('172.16.0.0/12 does not match 172.32.0.1', () => expect(isIPv4InCIDR('172.32.0.1', '172.16.0.0/12')).toBe(false));
    it('192.168.0.0/16 matches 192.168.1.1', () => expect(isIPv4InCIDR('192.168.1.1', '192.168.0.0/16')).toBe(true));
  });

  describe('link-local range', () => {
    it('matches 169.254.169.254', () => expect(isIPv4InCIDR('169.254.169.254', '169.254.0.0/16')).toBe(true));
    it('matches 169.254.0.1', () => expect(isIPv4InCIDR('169.254.0.1', '169.254.0.0/16')).toBe(true));
    it('does not match 169.253.255.255', () => expect(isIPv4InCIDR('169.253.255.255', '169.254.0.0/16')).toBe(false));
  });

  describe('/32 (single IP)', () => {
    it('matches exactly', () => expect(isIPv4InCIDR('10.0.0.5', '10.0.0.5/32')).toBe(true));
    it('does not match adjacent', () => expect(isIPv4InCIDR('10.0.0.6', '10.0.0.5/32')).toBe(false));
  });
});

describe('isIPv6InCIDR', () => {
  it('matches ::1/128 (loopback)', () => {
    expect(isIPv6InCIDR('::1', '::1/128')).toBe(true);
  });

  it('does not match ::2 in ::1/128', () => {
    expect(isIPv6InCIDR('::2', '::1/128')).toBe(false);
  });

  it('matches fe80:: in fe80::/10', () => {
    expect(isIPv6InCIDR('fe80::1', 'fe80::/10')).toBe(true);
  });

  it('matches fc00:: in fc00::/7', () => {
    expect(isIPv6InCIDR('fc00::1', 'fc00::/7')).toBe(true);
  });
});

describe('isInCIDR (unified)', () => {
  it('auto-detects IPv4 CIDR', () => {
    expect(isInCIDR('192.168.1.1', '192.168.0.0/16')).toBe(true);
  });

  it('auto-detects IPv6 CIDR', () => {
    expect(isInCIDR('::1', '::1/128')).toBe(true);
  });

  it('returns false for malformed input without throwing', () => {
    expect(isInCIDR('not-an-ip', '10.0.0.0/8')).toBe(false);
  });
});

