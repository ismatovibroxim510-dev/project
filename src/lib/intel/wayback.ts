import { cached } from "./cache";
import { fetchJson, SourceError } from "./http";
import type { WaybackIntel } from "./types";

export { snapshotUrl, timestampToDate } from "./wayback-shared";

const TTL_MS = 24 * 60 * 60 * 1000;
const TS_RE = /^(19|20)\d{12}$/;

function validTimestamp(v: unknown): string | null {
  return typeof v === "string" && TS_RE.test(v) ? v : null;
}

/** CDX JSON output: [["timestamp","statuscode"], ["20080514210148","200"]] */
export function parseCdxFirst(data: unknown): string | null {
  if (!Array.isArray(data) || data.length < 2 || !Array.isArray(data[1])) return null;
  return validTimestamp(data[1][0]);
}

/** Sparkline JSON: { first_ts, last_ts, years: { "2008": [12 monthly counts] } } */
export function parseSparkline(data: unknown): { first: string | null; last: string | null; captures: number | null } {
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new SourceError("unexpected response");
  const d = data as Record<string, unknown>;
  let captures: number | null = null;
  if (d.years && typeof d.years === "object" && !Array.isArray(d.years)) {
    captures = 0;
    for (const [year, months] of Object.entries(d.years).slice(0, 60)) {
      if (!/^\d{4}$/.test(year) || !Array.isArray(months)) continue;
      for (const n of months.slice(0, 12)) if (Number.isInteger(n) && n >= 0 && n < 1e8) captures += n;
    }
  }
  return { first: validTimestamp(d.first_ts), last: validTimestamp(d.last_ts), captures };
}

export function getWayback(domain: string): Promise<WaybackIntel | null> {
  return cached(`wayback:${domain}`, TTL_MS, async () => {
    const q = encodeURIComponent(domain);
    // First capture from the documented CDX API; latest capture and counts from the sparkline
    // endpoint the Wayback calendar uses (the CDX "latest" query is too slow for a 5s budget).
    const [first, spark] = await Promise.all([
      fetchJson(
        `https://web.archive.org/cdx/search/cdx?url=${q}&output=json&limit=1&fl=timestamp,statuscode`,
        16 * 1024,
      )
        .then(parseCdxFirst)
        .catch(() => null),
      fetchJson(`https://web.archive.org/__wb/sparkline?output=json&url=${q}&collection=web`, 256 * 1024)
        .then((d) => (d === null ? null : parseSparkline(d)))
        .catch(() => null),
    ]);
    if (!first && !spark) throw new SourceError("Wayback Machine unavailable");
    const firstTimestamp = first ?? spark?.first ?? null;
    return {
      domain,
      firstTimestamp,
      lastTimestamp: spark?.last ?? null,
      captures: firstTimestamp ? (spark?.captures ?? null) : 0,
    };
  });
}
