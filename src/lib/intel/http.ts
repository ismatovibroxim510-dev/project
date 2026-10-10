import { fetchChain } from "@/lib/scanner/net";
import { site } from "@/lib/site";

export const USER_AGENT = `SiteGrade-Security-Scanner/1.0 (+${site.url})`;

export class SourceError extends Error {}

/**
 * GET JSON from a third-party API through the same SSRF-guarded client as the scanner
 * (safe DNS lookup on every hop, 5s timeout per request, max 5 redirects), with a
 * verified TLS certificate and a size cap. Returns null for 404 ("no data").
 * Throws SourceError on anything else (rate limits, errors, invalid JSON).
 */
export async function fetchJson(url: string, maxBytes: number, accept = "application/json"): Promise<unknown | null> {
  const chain = await fetchChain(url, {
    maxBodyBytes: maxBytes,
    verifyTls: true,
    headers: { Accept: accept, "User-Agent": USER_AGENT },
  });
  const hop = chain.hops.at(-1);
  if (!hop) throw new SourceError(chain.error ?? chain.stoppedReason ?? "no response");
  if (hop.status === 404) return null;
  if (hop.status !== 200) throw new SourceError(`HTTP ${hop.status}`);
  if (hop.bodyTooLarge || hop.body === undefined) throw new SourceError("response too large");
  try {
    return JSON.parse(hop.body);
  } catch {
    throw new SourceError("invalid JSON");
  }
}
