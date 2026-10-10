import { cached } from "./cache";
import { fetchJson, SourceError } from "./http";
import { isoDate, text } from "./sanitize";
import type { RdapIntel } from "./types";

export { domainAgeDays, humanAge, rdapWarnings, type RdapWarning } from "./rdap-shared";

const TTL_MS = 24 * 60 * 60 * 1000;

function registrarName(entities: unknown): string | null {
  if (!Array.isArray(entities)) return null;
  for (const e of entities.slice(0, 20)) {
    if (!e || typeof e !== "object") continue;
    const entity = e as Record<string, unknown>;
    if (!Array.isArray(entity.roles) || !entity.roles.includes("registrar")) continue;
    // jCard: ["vcard", [["fn", {}, "text", "Registrar Name"], ...]]
    const vcard = entity.vcardArray;
    if (Array.isArray(vcard) && Array.isArray(vcard[1])) {
      for (const prop of vcard[1].slice(0, 30)) {
        if (Array.isArray(prop) && prop[0] === "fn") {
          const name = text(prop[3], 120);
          if (name) return name;
        }
      }
    }
  }
  return null;
}

/** Extract registration, expiry and update dates and the registrar from an RDAP domain object. */
export function parseRdap(data: unknown, domain: string): RdapIntel {
  if (!data || typeof data !== "object" || Array.isArray(data)) throw new SourceError("unexpected response");
  const d = data as Record<string, unknown>;
  if (d.objectClassName !== undefined && d.objectClassName !== "domain") throw new SourceError("not a domain object");
  const events = new Map<string, string>();
  if (Array.isArray(d.events)) {
    for (const e of d.events.slice(0, 30)) {
      if (!e || typeof e !== "object") continue;
      const ev = e as Record<string, unknown>;
      const action = typeof ev.eventAction === "string" ? ev.eventAction.toLowerCase() : "";
      const date = isoDate(ev.eventDate);
      if (action && date && !events.has(action)) events.set(action, date);
    }
  }
  const result: RdapIntel = {
    domain,
    registered: events.get("registration") ?? null,
    expires: events.get("expiration") ?? null,
    updated: events.get("last changed") ?? null,
    registrar: registrarName(d.entities),
  };
  if (!result.registered && !result.expires && !result.registrar) throw new SourceError("no usable data");
  return result;
}

export function getRdap(domain: string): Promise<RdapIntel | null> {
  return cached(`rdap:${domain}`, TTL_MS, async () => {
    // rdap.org redirects to the registry's own RDAP server; redirects go through the SSRF-guarded client.
    const data = await fetchJson(
      `https://rdap.org/domain/${encodeURIComponent(domain)}`,
      256 * 1024,
      "application/rdap+json, application/json",
    );
    return data === null ? null : parseRdap(data, domain);
  });
}
