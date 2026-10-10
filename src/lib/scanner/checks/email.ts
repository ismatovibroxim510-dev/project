import { Resolver } from "node:dns/promises";
import { withTimeout, REQUEST_TIMEOUT_MS } from "../net";
import type { CategoryResult, Finding } from "../types";
import { category, finding } from "../util";

type TxtResult = { records: string[] } | { error: string };

function makeResolver() {
  // Per-query timeout well under our 5s budget, with one retry.
  return new Resolver({ timeout: 2000, tries: 2 });
}

async function lookupTxt(resolver: Resolver, name: string): Promise<TxtResult> {
  try {
    const rows = await withTimeout(resolver.resolveTxt(name), REQUEST_TIMEOUT_MS, "DNS query timed out");
    return { records: rows.map((chunks) => chunks.join("")) };
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code;
    if (code === "ENODATA" || code === "ENOTFOUND") return { records: [] };
    return { error: code ?? "DNS error" };
  }
}

function checkSpf(domain: string, result: TxtResult): Finding {
  const base = {
    id: "spf",
    title: "SPF record",
    maxPoints: 5,
    explanation:
      'SPF lists which mail servers are allowed to send email for this domain. Receiving servers use it to spot forged "From" addresses used in phishing.',
  };
  const fix = `Publish one TXT record on ${domain} like \`v=spf1 include:_spf.google.com -all\` (replace the include with your email provider's). If the domain never sends email, use \`v=spf1 -all\`.`;

  if ("error" in result) {
    return finding({ ...base, status: "warn", points: 2, summary: `Could not look up TXT records (${result.error}).` });
  }
  const spf = result.records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim()));
  if (spf.length === 0) return finding({ ...base, status: "fail", points: 0, summary: "No SPF record found.", fix });
  if (spf.length > 1) {
    return finding({
      ...base,
      status: "fail",
      points: 0,
      summary: `${spf.length} SPF records found. Multiple records make SPF invalid (permerror), so it is ignored.`,
      fix: "Merge them into a single `v=spf1 ... -all` TXT record.",
      evidence: spf.join("\n"),
    });
  }
  const record = spf[0].trim();
  const all = record.match(/(?:^|\s)([+\-~?]?)all(?:\s|$)/i);
  const evidence = record;
  if (!all) {
    if (/(?:^|\s)redirect=/i.test(record)) {
      return finding({
        ...base,
        status: "pass",
        points: 5,
        summary: "SPF record found; policy is delegated with redirect=.",
        evidence,
      });
    }
    return finding({
      ...base,
      status: "warn",
      points: 2,
      summary: 'SPF record has no "all" mechanism, so unlisted senders are treated as neutral.',
      fix: "End the record with `-all` (or `~all`) so mail from unlisted servers is rejected or flagged.",
      evidence,
    });
  }
  switch (all[1]) {
    case "-":
      return finding({
        ...base,
        status: "pass",
        points: 5,
        summary: "SPF record found with a strict -all policy (hard fail).",
        evidence,
      });
    case "~":
      return finding({
        ...base,
        status: "pass",
        points: 4,
        summary: "SPF record found with ~all (soft fail). Common and acceptable alongside an enforcing DMARC policy.",
        fix: "For maximum strictness, switch ~all to -all once you're confident all your senders are listed.",
        evidence,
      });
    case "?":
      return finding({
        ...base,
        status: "warn",
        points: 2,
        summary: "SPF ends in ?all (neutral), which gives receivers no guidance about forged mail.",
        fix: "Change ?all to ~all or -all.",
        evidence,
      });
    default:
      return finding({
        ...base,
        status: "fail",
        points: 0,
        summary: "SPF ends in +all, which authorises every server on the internet to send as this domain.",
        fix: "Change +all to -all immediately and list only your real mail servers.",
        evidence,
      });
  }
}

interface DmarcLookup {
  record: string | null;
  /** Domain where the record was found (may be a parent domain). */
  foundAt: string | null;
  error: string | null;
}

/** RFC 7489: if no record on the exact domain, fall back to the parent (organizational) domain. */
async function findDmarc(resolver: Resolver, domain: string): Promise<DmarcLookup> {
  const labels = domain.split(".");
  for (let i = 0; i <= labels.length - 2; i++) {
    const candidate = labels.slice(i).join(".");
    const result = await lookupTxt(resolver, `_dmarc.${candidate}`);
    if ("error" in result) return { record: null, foundAt: null, error: result.error };
    const records = result.records.filter((r) => /^v=DMARC1(\s*;|\s*$)/i.test(r.trim()));
    if (records.length > 1) return { record: records.join("\n"), foundAt: candidate, error: "multiple" };
    if (records.length === 1) return { record: records[0].trim(), foundAt: candidate, error: null };
  }
  return { record: null, foundAt: null, error: null };
}

function checkDmarc(domain: string, lookup: DmarcLookup): Finding {
  const base = {
    id: "dmarc",
    title: "DMARC policy",
    maxPoints: 7,
    explanation:
      "DMARC tells receiving mail servers what to do with email that fails SPF/DKIM checks: nothing (none), send to spam (quarantine) or block it (reject). Without an enforcing policy, attackers can send convincing phishing emails from this domain.",
  };
  const fix = `Publish a TXT record at _dmarc.${domain}: start with \`v=DMARC1; p=none; rua=mailto:dmarc@${domain}\` to collect reports, then move to \`p=quarantine\` and finally \`p=reject\` once legitimate mail passes.`;

  if (lookup.error === "multiple") {
    return finding({
      ...base,
      status: "fail",
      points: 0,
      summary: "Multiple DMARC records found. Receivers ignore DMARC when there's more than one.",
      fix: "Keep exactly one v=DMARC1 TXT record.",
      evidence: lookup.record ?? undefined,
    });
  }
  if (lookup.error) {
    return finding({
      ...base,
      status: "warn",
      points: 2,
      summary: `Could not look up the DMARC record (${lookup.error}).`,
    });
  }
  if (!lookup.record || !lookup.foundAt) {
    return finding({ ...base, status: "fail", points: 0, summary: "No DMARC record found.", fix });
  }

  const tags = new Map<string, string>();
  for (const part of lookup.record.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    tags.set(
      part.slice(0, eq).trim().toLowerCase(),
      part
        .slice(eq + 1)
        .trim()
        .toLowerCase(),
    );
  }
  const inherited = lookup.foundAt !== domain;
  // A subdomain inherits the parent's sp= policy if set, otherwise p=.
  const policy = (inherited && tags.get("sp")) || tags.get("p");
  const pct = tags.has("pct") ? Number(tags.get("pct")) : 100;
  const where = inherited ? ` (inherited from ${lookup.foundAt})` : "";
  const evidence = `_dmarc.${lookup.foundAt}: ${lookup.record}`;

  if (policy === "reject" || policy === "quarantine") {
    const full = policy === "reject" ? 7 : 6;
    if (pct < 100) {
      return finding({
        ...base,
        status: "warn",
        points: full - 3,
        summary: `Policy is ${policy}${where}, but only applied to ${pct}% of failing mail.`,
        fix: "Remove the pct tag (or set pct=100) so the policy applies to all failing mail.",
        evidence,
      });
    }
    return finding({
      ...base,
      status: "pass",
      points: full,
      summary:
        policy === "reject"
          ? `Policy is reject${where}: forged email is blocked.`
          : `Policy is quarantine${where}: forged email goes to spam.`,
      fix: policy === "reject" ? undefined : "When you're confident, move to p=reject for the strongest protection.",
      evidence,
    });
  }
  if (policy === "none") {
    return finding({
      ...base,
      status: "warn",
      points: 2,
      summary: `Policy is none${where}: failures are only reported, forged email is still delivered.`,
      fix: "Review your DMARC reports, make sure legitimate senders pass SPF/DKIM, then change to p=quarantine and later p=reject.",
      evidence,
    });
  }
  return finding({
    ...base,
    status: "fail",
    points: 0,
    summary: `DMARC record${where} has a missing or invalid p= policy.`,
    fix,
    evidence,
  });
}

export async function checkEmail(
  host: string,
): Promise<{ category: CategoryResult; domain: string; spfRecord: string | null }> {
  // Email is configured on the bare domain, not on www.
  const domain = host.startsWith("www.") ? host.slice(4) : host;
  const resolver = makeResolver();
  const [txt, dmarc] = await Promise.all([lookupTxt(resolver, domain), findDmarc(resolver, domain)]);
  const spf = "records" in txt ? txt.records.filter((r) => /^v=spf1(\s|$)/i.test(r.trim())) : [];
  return {
    category: category("email", [checkSpf(domain, txt), checkDmarc(domain, dmarc)]),
    domain,
    spfRecord: spf.length === 1 ? spf[0].trim() : null,
  };
}
