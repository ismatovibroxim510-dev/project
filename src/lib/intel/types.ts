/** "Hacker's View": what anyone can learn about a site from free public data sources. */

export type IntelSource = "shodan" | "breaches" | "rdap" | "wayback" | "geo";

export const INTEL_ORDER: IntelSource[] = ["shodan", "breaches", "rdap", "wayback", "geo"];

export type PortKind = "database" | "remote-admin" | "web" | "mail" | "file-transfer" | "dns" | "other";

export interface PortInfo {
  port: number;
  label: string;
  kind: PortKind;
  /** Databases and remote-admin services reachable from the internet. */
  highRisk: boolean;
}

export interface ShodanHost {
  ip: string;
  ports: PortInfo[];
  /** Capped list; cveTotal is the real count. */
  cves: string[];
  cveTotal: number;
  cpes: string[];
  tags: string[];
  hostnames: string[];
}

export interface ShodanIntel {
  /** Hosts Shodan had data for (others are listed in `noData`). */
  hosts: ShodanHost[];
  noData: string[];
}

export interface Breach {
  name: string;
  title: string;
  /** YYYY-MM-DD */
  date: string | null;
  pwnCount: number;
  dataClasses: string[];
  verified: boolean;
  /** Plain text (HTML stripped). */
  description: string;
}

export interface BreachIntel {
  domain: string;
  breaches: Breach[];
  total: number;
}

export interface RdapIntel {
  domain: string;
  registered: string | null;
  expires: string | null;
  updated: string | null;
  registrar: string | null;
}

export interface WaybackIntel {
  domain: string;
  /** 14-digit Wayback timestamps (yyyyMMddhhmmss). */
  firstTimestamp: string | null;
  lastTimestamp: string | null;
  /** Approximate number of captures, if known. */
  captures: number | null;
}

export interface GeoIntel {
  ip: string;
  country: string | null;
  countryCode: string | null;
  region: string | null;
  city: string | null;
  latitude: number | null;
  longitude: number | null;
  asn: number | null;
  org: string | null;
  isp: string | null;
}

export interface IntelDataMap {
  shodan: ShodanIntel;
  breaches: BreachIntel;
  rdap: RdapIntel;
  wayback: WaybackIntel;
  geo: GeoIntel;
}

/** undefined = still loading, null = unavailable (card hidden). */
export type IntelState = { [K in IntelSource]?: IntelDataMap[K] | null };
