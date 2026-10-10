import { clientIp, rateLimit } from "@/lib/rate-limit";
import { startIntel } from "@/lib/intel";
import { INTEL_ORDER, type IntelSource } from "@/lib/intel/types";
import { BlockedAddressError, DomainError, normalizeDomain, resolvePublicAll, runScan, ScanError } from "@/lib/scanner";
import type { ScanEvent } from "@/lib/scanner/types";
import { CATEGORY_ORDER } from "@/lib/scanner/types";

// The scanner needs Node's `tls` and `dns` modules.
export const runtime = "nodejs";
// Every request has a 5s timeout and chains are capped at 6 requests (30s). Everything runs in
// parallel except the robots.txt fallback for HTTP-only sites, so 60s covers the worst case.
// Public-data sources have a 12s ceiling each and run in parallel with the scan.
export const maxDuration = 60;

const RATE_LIMIT_MAX = Number(process.env.RATE_LIMIT_MAX ?? 10);
const RATE_LIMIT_WINDOW_MS = Number(process.env.RATE_LIMIT_WINDOW_SECONDS ?? 300) * 1000;
const MAX_BODY_BYTES = 1024;

function jsonError(message: string, status: number, extraHeaders: Record<string, string> = {}) {
  return Response.json({ error: message }, { status, headers: { "Cache-Control": "no-store", ...extraHeaders } });
}

export async function POST(request: Request) {
  if (!request.headers.get("content-type")?.toLowerCase().startsWith("application/json")) {
    return jsonError("Expected a JSON body.", 415);
  }

  const raw = await request.text();
  if (raw.length > MAX_BODY_BYTES) return jsonError("Request body too large.", 413);

  let domainInput: unknown;
  try {
    domainInput = (JSON.parse(raw) as { domain?: unknown })?.domain;
  } catch {
    return jsonError("Invalid JSON body.", 400);
  }

  let host: string;
  try {
    host = normalizeDomain(domainInput);
  } catch (e) {
    if (e instanceof DomainError) return jsonError(e.message, 400);
    throw e;
  }

  // Rate-limit only valid requests so typos don't burn a user's quota.
  const limit = rateLimit(clientIp(request.headers), RATE_LIMIT_MAX, RATE_LIMIT_WINDOW_MS);
  if (!limit.ok) {
    return jsonError(`Too many scans. Please wait ${limit.retryAfterSeconds} seconds and try again.`, 429, {
      "Retry-After": String(limit.retryAfterSeconds),
    });
  }

  // SSRF guard, part 1: refuse up front if the domain points at private/reserved
  // space. (Part 2 is in the socket lookup used by every connection, including redirects.)
  let ips: string[];
  try {
    ips = await resolvePublicAll(host);
  } catch (e) {
    if (e instanceof BlockedAddressError) {
      return jsonError("This domain resolves to a private or reserved IP address and can't be scanned.", 400);
    }
    return jsonError(`Couldn't resolve ${host}. Check the spelling and that the domain exists.`, 422);
  }

  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      const send = (event: ScanEvent) => {
        try {
          controller.enqueue(encoder.encode(JSON.stringify(event) + "\n"));
        } catch {
          // Client disconnected; nothing to do.
        }
      };
      send({ type: "start", domain: host, checks: CATEGORY_ORDER });
      // Public-data lookups ("Hacker's View") run alongside the scan and never contact the target.
      // Each resolves to validated data or null, and is streamed as soon as it's ready.
      const intel = startIntel(host, ips);
      const intelSent = INTEL_ORDER.map((source: IntelSource) =>
        intel[source].then((data) => send({ type: "intel", source, data } as ScanEvent)),
      );
      try {
        const report = await runScan(host, ips[0], (id, status) => send({ type: "check", id, status }), intel.shodan);
        send({ type: "result", report });
        await Promise.all(intelSent);
      } catch (e) {
        const message = e instanceof ScanError ? e.message : "The scan failed unexpectedly. Please try again.";
        if (!(e instanceof ScanError)) console.error("scan failed", host, e);
        send({ type: "error", message });
      } finally {
        try {
          controller.close();
        } catch {}
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "application/x-ndjson; charset=utf-8",
      "Cache-Control": "no-store",
      "X-RateLimit-Remaining": String(limit.remaining),
    },
  });
}
