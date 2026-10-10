import { getGeo } from "./geo";
import { getBreaches } from "./hibp";
import { getRdap } from "./rdap";
import { registrableDomain } from "./sanitize";
import { getShodan } from "./shodan";
import type { IntelDataMap, IntelSource } from "./types";
import { getWayback } from "./wayback";

export type IntelPromises = { [K in IntelSource]: Promise<IntelDataMap[K] | null> };

/** Hard ceiling per source, on top of the 5s per-request timeouts (RDAP may follow a redirect). */
const SOURCE_DEADLINE_MS = 12000;

function settle<T>(p: Promise<T | null>): Promise<T | null> {
  let timer: NodeJS.Timeout;
  return Promise.race([
    p.catch(() => null),
    new Promise<null>((resolve) => {
      timer = setTimeout(() => resolve(null), SOURCE_DEADLINE_MS);
    }),
  ]).finally(() => clearTimeout(timer));
}

/**
 * Start every public-data lookup in parallel. Each promise resolves to validated
 * data, or null when the source failed, timed out or was rate-limited. None reject.
 * Nothing here contacts the scanned site.
 */
export function startIntel(host: string, ips: string[]): IntelPromises {
  const domain = registrableDomain(host);
  return {
    shodan: settle(getShodan(ips)),
    breaches: settle(getBreaches(domain)),
    rdap: settle(getRdap(domain)),
    wayback: settle(getWayback(domain)),
    geo: settle(getGeo(ips[0] ?? null)),
  };
}
