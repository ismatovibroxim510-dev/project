import { isIP } from "node:net";
import { isPublicIp } from "@/lib/scanner/ip";
import { cached } from "./cache";
import { fetchJson, SourceError } from "./http";
import { finiteNumber, text } from "./sanitize";
import type { GeoIntel } from "./types";

const TTL_MS = 24 * 60 * 60 * 1000;

/** Validate an ipwho.is response. */
export function parseGeo(data: unknown, ip: string): GeoIntel {
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new SourceError("unexpected response");
  const d = data as Record<string, unknown>;
  if (d.success !== true || d.ip !== ip) throw new SourceError("lookup failed");
  const conn = d.connection && typeof d.connection === "object" ? (d.connection as Record<string, unknown>) : {};
  const code = text(d.country_code, 2);
  const lat = finiteNumber(d.latitude, -90, 90);
  const lon = finiteNumber(d.longitude, -180, 180);
  return {
    ip,
    country: text(d.country, 80),
    countryCode: code && /^[A-Z]{2}$/.test(code) ? code : null,
    region: text(d.region, 80),
    city: text(d.city, 80),
    // Only keep coordinates as a pair, and not the (0,0) "unknown" placeholder.
    latitude: lat !== null && lon !== null && !(lat === 0 && lon === 0) ? lat : null,
    longitude: lat !== null && lon !== null && !(lat === 0 && lon === 0) ? lon : null,
    asn: finiteNumber(conn.asn, 1, 4294967295),
    org: text(conn.org, 120),
    isp: text(conn.isp, 120),
  };
}

export function getGeo(ip: string | null): Promise<GeoIntel | null> {
  if (!ip || !isIP(ip) || !isPublicIp(ip)) return Promise.resolve(null);
  return cached(`geo:${ip}`, TTL_MS, async () => {
    const data = await fetchJson(`https://ipwho.is/${encodeURIComponent(ip)}`, 32 * 1024);
    return data === null ? null : parseGeo(data, ip);
  });
}
