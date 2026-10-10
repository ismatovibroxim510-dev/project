import dgram from "node:dgram";
import dns from "node:dns";
import { randomInt } from "node:crypto";
import { isIPv4, isIPv6 } from "node:net";

/**
 * Minimal DNS-over-UDP client, used only for record types Node's resolver API
 * doesn't expose (DS, and SOA ownership for finding the zone apex). Queries go to
 * the system's configured resolver - never to the scanned site.
 */

export const DNS_TYPES = { A: 1, NS: 2, CNAME: 5, SOA: 6, TXT: 16, AAAA: 28, DS: 43, RRSIG: 46, DNSKEY: 48 } as const;

export interface DnsRecord {
  name: string;
  type: number;
}

export interface DnsResponse {
  id: number;
  rcode: number;
  /** Authenticated Data: the resolver validated the answer with DNSSEC. */
  ad: boolean;
  truncated: boolean;
  answers: DnsRecord[];
  authority: DnsRecord[];
}

export function encodeQuery(name: string, type: number, id: number): Buffer {
  const labels = name.replace(/\.$/, "").split(".");
  const qname = Buffer.concat([
    ...labels.map((l) => {
      const b = Buffer.from(l, "ascii");
      if (b.length < 1 || b.length > 63) throw new Error("Invalid DNS label");
      return Buffer.concat([Buffer.from([b.length]), b]);
    }),
    Buffer.from([0]),
  ]);
  const header = Buffer.alloc(12);
  header.writeUInt16BE(id, 0);
  header.writeUInt16BE(0x0120, 2); // RD (recursion desired) + AD (ask for authenticated data)
  header.writeUInt16BE(1, 4); // QDCOUNT
  header.writeUInt16BE(1, 10); // ARCOUNT (EDNS0 OPT record)
  const question = Buffer.alloc(4);
  question.writeUInt16BE(type, 0);
  question.writeUInt16BE(1, 2); // class IN
  // OPT pseudo-record: root name, type 41, UDP payload 1232, DO bit set.
  const opt = Buffer.from([0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0]);
  return Buffer.concat([header, qname, question, opt]);
}

/** Read a (possibly compressed) domain name. Returns the name and the offset after it. */
export function readName(buf: Buffer, offset: number): { name: string; next: number } {
  const labels: string[] = [];
  let pos = offset;
  let next = -1;
  for (let jumps = 0; jumps < 64; jumps++) {
    if (pos >= buf.length) throw new Error("DNS name out of bounds");
    const len = buf[pos];
    if (len === 0) {
      return { name: labels.join(".").toLowerCase(), next: next === -1 ? pos + 1 : next };
    }
    if ((len & 0xc0) === 0xc0) {
      if (pos + 1 >= buf.length) throw new Error("DNS pointer out of bounds");
      if (next === -1) next = pos + 2;
      pos = ((len & 0x3f) << 8) | buf[pos + 1];
      continue;
    }
    if (pos + 1 + len > buf.length) throw new Error("DNS label out of bounds");
    labels.push(buf.toString("ascii", pos + 1, pos + 1 + len));
    pos += 1 + len;
  }
  throw new Error("DNS name has too many compression pointers");
}

export function parseResponse(buf: Buffer): DnsResponse {
  if (buf.length < 12) throw new Error("DNS response too short");
  const flags = buf.readUInt16BE(2);
  const qd = buf.readUInt16BE(4);
  const an = buf.readUInt16BE(6);
  const ns = buf.readUInt16BE(8);
  let pos = 12;
  for (let i = 0; i < qd; i++) pos = readName(buf, pos).next + 4;
  const readRecords = (count: number) => {
    const out: DnsRecord[] = [];
    for (let i = 0; i < count; i++) {
      const { name, next } = readName(buf, pos);
      if (next + 10 > buf.length) throw new Error("DNS record out of bounds");
      const type = buf.readUInt16BE(next);
      const rdlength = buf.readUInt16BE(next + 8);
      pos = next + 10 + rdlength;
      if (pos > buf.length) throw new Error("DNS rdata out of bounds");
      out.push({ name, type });
    }
    return out;
  };
  const answers = readRecords(an);
  const authority = readRecords(ns);
  return {
    id: buf.readUInt16BE(0),
    rcode: flags & 0x0f,
    ad: (flags & 0x0020) !== 0,
    truncated: (flags & 0x0200) !== 0,
    answers,
    authority,
  };
}

/** The system resolvers, usable ones first (link-local IPv6 needs a scope id we don't have). */
function resolverAddresses(): string[] {
  return dns
    .getServers()
    .map((s) => s.replace(/^\[([^\]]+)\](:\d+)?$/, "$1").replace(/^(\d+\.\d+\.\d+\.\d+):\d+$/, "$1"))
    .filter((s) => (isIPv4(s) || isIPv6(s)) && !/^fe80:/i.test(s))
    .sort((a, b) => Number(isIPv6(a)) - Number(isIPv6(b)));
}

function queryServer(server: string, name: string, type: number, timeoutMs: number): Promise<DnsResponse> {
  return new Promise((resolve, reject) => {
    const id = randomInt(0, 0xffff);
    const socket = dgram.createSocket(isIPv6(server) ? "udp6" : "udp4");
    const done = (fn: () => void) => {
      clearTimeout(timer);
      socket.close();
      fn();
    };
    const timer = setTimeout(() => done(() => reject(new Error("DNS query timed out"))), timeoutMs);
    socket.on("error", (err) => done(() => reject(err)));
    socket.on("message", (msg) => {
      try {
        const res = parseResponse(msg);
        if (res.id !== id) return; // not our answer; keep waiting
        done(() => resolve(res));
      } catch (e) {
        done(() => reject(e));
      }
    });
    socket.send(encodeQuery(name, type, id), 53, server);
  });
}

export async function query(name: string, type: number, timeoutMs = 2500): Promise<DnsResponse> {
  const servers = resolverAddresses().slice(0, 2);
  if (!servers.length) throw new Error("No DNS resolver configured");
  let lastError: unknown;
  for (const server of servers) {
    try {
      return await queryServer(server, name, type, timeoutMs);
    } catch (e) {
      lastError = e;
    }
  }
  throw lastError;
}

function parent(name: string): string {
  return name.split(".").slice(1).join(".");
}

/**
 * Find the DNS zone a name belongs to (e.g. www.example.co.uk -> example.co.uk)
 * by asking for its SOA record. Names with a CNAME are skipped by walking up.
 */
export async function findZone(host: string, q: typeof query = query): Promise<string | null> {
  for (let name = host; name.split(".").length >= 2; name = parent(name)) {
    const res = await q(name, DNS_TYPES.SOA);
    const soa = res.answers.find((r) => r.type === DNS_TYPES.SOA && r.name === name);
    if (soa) return name;
    if (res.answers.some((r) => r.type === DNS_TYPES.CNAME)) continue;
    const auth = res.authority.find((r) => r.type === DNS_TYPES.SOA);
    if (auth && (name === auth.name || name.endsWith(`.${auth.name}`))) return auth.name;
  }
  return null;
}

export interface DnssecStatus {
  status: "signed" | "unsigned" | "unknown";
  zone: string | null;
  /** True when the resolver reported the answer as DNSSEC-validated. */
  validated: boolean;
}

/** A zone is signed when its parent publishes a DS record for it. */
export async function dnssecStatus(host: string, q: typeof query = query): Promise<DnssecStatus> {
  try {
    const zone = await findZone(host, q);
    if (!zone) return { status: "unknown", zone: null, validated: false };
    const res = await q(zone, DNS_TYPES.DS);
    if (res.rcode !== 0) return { status: "unknown", zone, validated: false };
    const signed = res.answers.some((r) => r.type === DNS_TYPES.DS && r.name === zone);
    return { status: signed ? "signed" : "unsigned", zone, validated: res.ad };
  } catch {
    return { status: "unknown", zone: null, validated: false };
  }
}
