import { cached } from "./cache";
import { fetchJson, SourceError } from "./http";
import { finiteNumber, stringList, stripHtml, text } from "./sanitize";
import type { Breach, BreachIntel } from "./types";

const TTL_MS = 24 * 60 * 60 * 1000;
export const BREACH_DISPLAY_LIMIT = 10;
const NAME_RE = /^[A-Za-z0-9._ -]{1,80}$/;

/** Validate HIBP's breach list. Descriptions arrive as HTML and are reduced to plain text. */
export function parseBreaches(data: unknown, domain: string): BreachIntel {
  if (!Array.isArray(data)) throw new SourceError("unexpected response");
  const breaches: Breach[] = [];
  for (const item of data.slice(0, 200)) {
    if (!item || typeof item !== "object") continue;
    const b = item as Record<string, unknown>;
    const name = text(b.Name, 80);
    if (!name || !NAME_RE.test(name)) continue;
    // Fabricated and spam-list entries aren't real breaches of the site.
    if (b.IsFabricated === true || b.IsSpamList === true) continue;
    const date = typeof b.BreachDate === "string" && /^\d{4}-\d{2}-\d{2}$/.test(b.BreachDate) ? b.BreachDate : null;
    breaches.push({
      name,
      title: text(b.Title, 100) ?? name,
      date,
      pwnCount: finiteNumber(b.PwnCount, 0, 1e11) ?? 0,
      dataClasses: stringList(b.DataClasses, 15, 60),
      verified: b.IsVerified === true,
      description: stripHtml(b.Description, 700) ?? "",
    });
  }
  breaches.sort((a, b) => (b.date ?? "").localeCompare(a.date ?? ""));
  return { domain, breaches: breaches.slice(0, BREACH_DISPLAY_LIMIT), total: breaches.length };
}

export function getBreaches(domain: string): Promise<BreachIntel | null> {
  return cached(`hibp:${domain}`, TTL_MS, async () => {
    const data = await fetchJson(
      `https://haveibeenpwned.com/api/v3/breaches?domain=${encodeURIComponent(domain)}`,
      512 * 1024,
    );
    return parseBreaches(data ?? [], domain);
  });
}
