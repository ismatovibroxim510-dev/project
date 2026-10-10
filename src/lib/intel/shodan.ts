import { isIP } from "node:net";
import { isPublicIp } from "@/lib/scanner/ip";
import type { Penalty } from "@/lib/scanner/types";
import { cached } from "./cache";
import { EXPOSURE_RULES } from "./exposure-rules";
import { fetchJson, SourceError } from "./http";
import { stringList } from "./sanitize";
import type { PortInfo, PortKind, ShodanHost, ShodanIntel } from "./types";

const TTL_MS = 12 * 60 * 60 * 1000;
const MAX_IPS = 2;
const MAX_PORTS = 50;
export const CVE_DISPLAY_LIMIT = 15;
export { EXPOSURE_RULES };

const PORTS: Record<number, [string, PortKind, boolean]> = {
  20: ["FTP data", "file-transfer", false],
  21: ["FTP", "file-transfer", false],
  22: ["SSH (remote login)", "remote-admin", true],
  23: ["Telnet (unencrypted remote login)", "remote-admin", true],
  25: ["SMTP (email)", "mail", false],
  53: ["DNS", "dns", false],
  80: ["HTTP (web)", "web", false],
  110: ["POP3 (email)", "mail", false],
  111: ["RPC portmapper", "remote-admin", true],
  135: ["Windows RPC", "remote-admin", true],
  139: ["NetBIOS (Windows file sharing)", "remote-admin", true],
  143: ["IMAP (email)", "mail", false],
  161: ["SNMP (device management)", "remote-admin", true],
  389: ["LDAP (directory)", "database", true],
  443: ["HTTPS (web)", "web", false],
  445: ["SMB (Windows file sharing)", "remote-admin", true],
  465: ["SMTPS (email)", "mail", false],
  587: ["SMTP submission (email)", "mail", false],
  636: ["LDAPS (directory)", "database", true],
  993: ["IMAPS (email)", "mail", false],
  995: ["POP3S (email)", "mail", false],
  1433: ["Microsoft SQL Server", "database", true],
  1521: ["Oracle Database", "database", true],
  2049: ["NFS (network file system)", "remote-admin", true],
  2082: ["cPanel", "remote-admin", true],
  2083: ["cPanel (TLS)", "remote-admin", true],
  2086: ["WHM", "remote-admin", true],
  2087: ["WHM (TLS)", "remote-admin", true],
  2222: ["SSH (alternate port)", "remote-admin", true],
  2375: ["Docker API (unencrypted)", "remote-admin", true],
  2376: ["Docker API", "remote-admin", true],
  2379: ["etcd", "database", true],
  3000: ["Web app (dev server)", "web", false],
  3306: ["MySQL / MariaDB", "database", true],
  3389: ["RDP (Windows Remote Desktop)", "remote-admin", true],
  5000: ["Web app", "web", false],
  5432: ["PostgreSQL", "database", true],
  5601: ["Kibana", "database", true],
  5900: ["VNC (remote desktop)", "remote-admin", true],
  5984: ["CouchDB", "database", true],
  5985: ["WinRM (Windows remote management)", "remote-admin", true],
  5986: ["WinRM (TLS)", "remote-admin", true],
  6379: ["Redis", "database", true],
  6443: ["Kubernetes API", "remote-admin", true],
  8080: ["HTTP (alternate)", "web", false],
  8086: ["InfluxDB", "database", true],
  8443: ["HTTPS (alternate)", "web", false],
  8888: ["HTTP (alternate)", "web", false],
  9042: ["Cassandra", "database", true],
  9200: ["Elasticsearch", "database", true],
  9300: ["Elasticsearch (cluster)", "database", true],
  10000: ["Webmin", "remote-admin", true],
  10250: ["Kubernetes kubelet", "remote-admin", true],
  11211: ["Memcached", "database", true],
  27017: ["MongoDB", "database", true],
  27018: ["MongoDB", "database", true],
};

export function describePort(port: number): PortInfo {
  const known = PORTS[port];
  return known
    ? { port, label: known[0], kind: known[1], highRisk: known[2] }
    : { port, label: "Unknown service", kind: "other", highRisk: false };
}

/** Extra HTTP(S) ports CDNs such as Cloudflare listen on at their edge (2082/2083 etc. are NOT cPanel there). */
const CDN_HTTP_PORTS = new Set([2052, 2082, 2086, 2095, 8080, 8880]);
const CDN_HTTPS_PORTS = new Set([2053, 2083, 2087, 2096, 8443]);

/** On a CDN edge server the open ports belong to the CDN, not to the site: never high risk. */
export function describeCdnPort(port: number): PortInfo {
  if (CDN_HTTP_PORTS.has(port)) return { port, label: "CDN proxy port (HTTP)", kind: "web", highRisk: false };
  if (CDN_HTTPS_PORTS.has(port)) return { port, label: "CDN proxy port (HTTPS)", kind: "web", highRisk: false };
  return { ...describePort(port), highRisk: false };
}

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const CPE_RE = /^cpe:\/[aho]:[a-z0-9._\-~%:+]{1,150}$/i;
const TAG_RE = /^[a-z0-9 _-]{1,30}$/i;
const HOST_RE = /^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$/i;

function cveSortKey(id: string): number {
  const [, year, num] = id.split("-");
  return Number(year) * 1e8 + Number(num);
}

/** Validate an InternetDB response for `ip`. Throws on anything that doesn't look right. */
export function parseInternetDb(data: unknown, ip: string): ShodanHost {
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new SourceError("unexpected response");
  const d = data as Record<string, unknown>;
  if (d.ip !== ip) throw new SourceError("response is for a different IP");
  const ports = Array.isArray(d.ports)
    ? [...new Set(d.ports.filter((p): p is number => Number.isInteger(p) && p > 0 && p <= 65535))]
        .sort((a, b) => a - b)
        .slice(0, MAX_PORTS)
    : [];
  const allCves = stringList(d.vulns, 2000, 20, CVE_RE).sort((a, b) => cveSortKey(b) - cveSortKey(a));
  const tags = stringList(d.tags, 10, 30, TAG_RE);
  const isCdn = tags.includes("cdn");
  return {
    ip,
    ports: ports.map(isCdn ? describeCdnPort : describePort),
    cves: allCves.slice(0, CVE_DISPLAY_LIMIT),
    cveTotal: allCves.length,
    cpes: stringList(d.cpes, 15, 160, CPE_RE),
    tags,
    hostnames: stringList(d.hostnames, 10, 253, HOST_RE),
  };
}

async function lookupIp(ip: string): Promise<ShodanHost | "no-data" | null> {
  const result = await cached(`shodan:${ip}`, TTL_MS, async () => {
    const data = await fetchJson(`https://internetdb.shodan.io/${encodeURIComponent(ip)}`, 64 * 1024);
    return data === null ? ("no-data" as const) : parseInternetDb(data, ip);
  });
  return result;
}

/** Look up to two public IPs. Returns null when every lookup failed (card hidden). */
export async function getShodan(ips: string[]): Promise<ShodanIntel | null> {
  const targets = ips.filter((ip) => isIP(ip) && isPublicIp(ip)).slice(0, MAX_IPS);
  if (!targets.length) return null;
  const results = await Promise.all(targets.map(lookupIp));
  if (results.every((r) => r === null)) return null;
  return {
    hosts: results.filter((r): r is ShodanHost => !!r && r !== "no-data"),
    noData: targets.filter((_, i) => results[i] === "no-data"),
  };
}

/** Score penalties from Shodan data: exposed high-risk services and known CVEs. */
export function exposurePenalties(intel: ShodanIntel | null): Penalty[] {
  if (!intel) return [];
  const ports = new Map<number, PortInfo>();
  for (const h of intel.hosts) for (const p of h.ports) if (p.highRisk) ports.set(p.port, p);
  // Two IPs of one site usually run the same software, so use the larger count rather than the sum.
  // CVEs on a CDN edge describe the CDN, not the site, so they don't count.
  const totalCves = Math.max(0, ...intel.hosts.filter((h) => !h.tags.includes("cdn")).map((h) => h.cveTotal));
  const penalties: Penalty[] = [];

  const db = [...ports.values()].filter((p) => p.kind === "database");
  const admin = [...ports.values()].filter((p) => p.kind !== "database");
  let portPoints = db.length * EXPOSURE_RULES.databasePort + admin.length * EXPOSURE_RULES.remoteAdminPort;
  portPoints = Math.min(portPoints, EXPOSURE_RULES.portCap);
  if (portPoints > 0) {
    penalties.push({
      id: "exposed-ports",
      label: "Exposed high-risk services",
      points: -portPoints,
      reason: `Reachable from the internet: ${[...db, ...admin].map((p) => `${p.port} ${p.label}`).join(", ")}.`,
      capsGrade: db.length ? "C" : undefined,
    });
  }
  if (totalCves > 0) {
    const pts = totalCves >= EXPOSURE_RULES.manyCvesThreshold ? EXPOSURE_RULES.manyCves : EXPOSURE_RULES.someCves;
    penalties.push({
      id: "known-cves",
      label: "Known vulnerabilities (CVEs)",
      points: -pts,
      reason: `Shodan matched ${totalCves} known CVE${totalCves === 1 ? "" : "s"} to the software versions it saw.`,
    });
  }
  // Apply the overall cap by trimming the last penalty.
  const total = penalties.reduce((s, p) => s - p.points, 0);
  if (total > EXPOSURE_RULES.totalCap && penalties.length) {
    const last = penalties[penalties.length - 1];
    last.points += total - EXPOSURE_RULES.totalCap;
  }
  return penalties;
}
