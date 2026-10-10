import { Resolver } from "node:dns/promises";
import { dnssecStatus, type DnssecStatus } from "../dnsraw";
import { REQUEST_TIMEOUT_MS, withTimeout } from "../net";
import type { CategoryResult, Finding } from "../types";
import { category, finding } from "../util";

export interface CaaLookup {
  records: Array<{ tag: string; value: string }>;
  /** Domain the records were found on (RFC 8659 climbs to parent domains). */
  foundAt: string | null;
  error: string | null;
}

export async function lookupCaa(host: string): Promise<CaaLookup> {
  const resolver = new Resolver({ timeout: 2000, tries: 2 });
  const labels = host.split(".");
  for (let i = 0; i < labels.length - 1; i++) {
    const name = labels.slice(i).join(".");
    try {
      const rows = await withTimeout(resolver.resolveCaa(name), REQUEST_TIMEOUT_MS, "DNS query timed out");
      if (rows.length) {
        const records = rows.flatMap((r) =>
          Object.entries(r)
            .filter(([k]) => k !== "critical" && k !== "type")
            .map(([tag, value]) => ({ tag, value: String(value) })),
        );
        return { records, foundAt: name, error: null };
      }
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code;
      if (code !== "ENODATA" && code !== "ENOTFOUND") return { records: [], foundAt: null, error: code ?? "DNS error" };
    }
  }
  return { records: [], foundAt: null, error: null };
}

export function caaFinding(host: string, caa: CaaLookup): Finding {
  const base = {
    id: "caa",
    title: "CAA record",
    maxPoints: 3,
    explanation:
      "A CAA record lists which certificate authorities are allowed to issue certificates for the domain. If an attacker tricks some other CA into issuing a certificate for your site, that CA is required to refuse.",
  };
  if (caa.error) {
    return finding({ ...base, status: "warn", points: 1, summary: `Could not look up CAA records (${caa.error}).` });
  }
  if (!caa.records.length) {
    return finding({
      ...base,
      status: "warn",
      points: 0,
      summary: "No CAA record, so any certificate authority may issue certificates for this domain.",
      fix: `Add a CAA record naming the authority you use, e.g. \`${host} CAA 0 issue "letsencrypt.org"\`.`,
    });
  }
  const issuers = caa.records.filter((r) => r.tag === "issue" || r.tag === "issuewild").map((r) => r.value);
  const inherited = caa.foundAt !== host ? ` (inherited from ${caa.foundAt})` : "";
  return finding({
    ...base,
    status: "pass",
    points: 3,
    summary: issuers.length
      ? `Only ${[...new Set(issuers.map((v) => v.split(";")[0].trim() || "nobody"))].join(", ")} may issue certificates${inherited}.`
      : `CAA record present${inherited}.`,
    evidence: caa.records.map((r) => `${caa.foundAt} CAA 0 ${r.tag} "${r.value}"`).join("\n"),
  });
}

export function dnssecFinding(dnssec: DnssecStatus): Finding {
  const base = {
    id: "dnssec",
    title: "DNSSEC",
    maxPoints: 3,
    explanation:
      "DNSSEC adds cryptographic signatures to DNS answers, so resolvers can detect forged responses that would send visitors (or email) to an attacker's server. It's enabled at your DNS provider and registrar.",
  };
  const fix =
    "Turn on DNSSEC in your DNS provider's dashboard (Cloudflare: DNS → Settings → DNSSEC; Route 53: DNSSEC signing), then add the DS record it gives you at your domain registrar.";
  if (dnssec.status === "unknown") {
    return finding({ ...base, status: "warn", points: 1, summary: "Could not determine whether DNSSEC is enabled." });
  }
  if (dnssec.status === "unsigned") {
    return finding({
      ...base,
      status: "warn",
      points: 0,
      summary: `DNSSEC is not enabled for ${dnssec.zone}.`,
      fix,
      evidence: `No DS record for ${dnssec.zone}`,
    });
  }
  return finding({
    ...base,
    status: "pass",
    points: 3,
    summary: `DNSSEC is enabled for ${dnssec.zone}${dnssec.validated ? " and the resolver validated the signatures" : ""}.`,
    evidence: `DS record published for ${dnssec.zone}${dnssec.validated ? " (AD flag set)" : ""}`,
  });
}

export async function checkDns(host: string): Promise<{ category: CategoryResult; caa: CaaLookup }> {
  const [caa, dnssec] = await Promise.all([lookupCaa(host), dnssecStatus(host)]);
  return { category: category("dns", [caaFinding(host, caa), dnssecFinding(dnssec)]), caa };
}
