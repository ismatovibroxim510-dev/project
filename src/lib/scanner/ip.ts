import { BlockList, isIPv4, isIPv6 } from "node:net";

/** IPv4 ranges that are not publicly routable (RFC 6890 special-purpose registry). */
const V4_DENY: Array<[string, number]> = [
  ["0.0.0.0", 8], // "this" network
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // carrier-grade NAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local (incl. cloud metadata 169.254.169.254)
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.0.2.0", 24], // TEST-NET-1
  ["192.31.196.0", 24], // AS112
  ["192.52.193.0", 24], // AMT
  ["192.88.99.0", 24], // 6to4 relay anycast
  ["192.168.0.0", 16], // private
  ["192.175.48.0", 24], // AS112
  ["198.18.0.0", 15], // benchmarking
  ["198.51.100.0", 24], // TEST-NET-2
  ["203.0.113.0", 24], // TEST-NET-3
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved + broadcast
];

/**
 * IPv6 is handled as an allow-list: only global unicast (2000::/3) is public,
 * minus special ranges inside it. Everything else (::1, ::, fc00::/7, fe80::/10,
 * ff00::/8, 64:ff9b::/96 NAT64, IPv4-compatible, ...) is blocked.
 */
const V6_ALLOW: Array<[string, number]> = [["2000::", 3]];
const V6_DENY: Array<[string, number]> = [
  ["2001::", 23], // IETF protocol assignments (incl. Teredo 2001::/32)
  ["2001:db8::", 32], // documentation
  ["2002::", 16], // 6to4 (embeds arbitrary IPv4)
  ["3fff::", 20], // documentation
];

const v4Deny = new BlockList();
for (const [net, prefix] of V4_DENY) v4Deny.addSubnet(net, prefix, "ipv4");
const v6Allow = new BlockList();
for (const [net, prefix] of V6_ALLOW) v6Allow.addSubnet(net, prefix, "ipv6");
const v6Deny = new BlockList();
for (const [net, prefix] of V6_DENY) v6Deny.addSubnet(net, prefix, "ipv6");

/** Returns true only for publicly routable unicast addresses. */
export function isPublicIp(address: string): boolean {
  let addr = address.trim();
  if (addr.startsWith("[") && addr.endsWith("]")) addr = addr.slice(1, -1);
  // Strip IPv6 zone index (fe80::1%eth0) - zones only exist on link-local anyway.
  const zone = addr.indexOf("%");
  if (zone !== -1) return false;

  // IPv4-mapped IPv6 (::ffff:a.b.c.d) -> judge by the embedded IPv4 address.
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(addr);
  if (mapped) addr = mapped[1];

  if (isIPv4(addr)) return !v4Deny.check(addr, "ipv4");
  if (isIPv6(addr)) return v6Allow.check(addr, "ipv6") && !v6Deny.check(addr, "ipv6");
  return false;
}
