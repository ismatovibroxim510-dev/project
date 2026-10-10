import { domainAgeDays, humanAge, rdapWarnings } from "@/lib/intel/rdap-shared";
import type { IntelState } from "@/lib/intel/types";
import { snapshotUrl, timestampToDate } from "@/lib/intel/wayback-shared";
import type { ScanReport, Status } from "@/lib/scanner/types";

const MARK: Record<Status, string> = { pass: "✓", warn: "!", fail: "✗", info: "i" };
const day = (iso: string) => iso.slice(0, 10);

function intelLines(intel: IntelState): string[] {
  const lines: string[] = [];
  const s = intel.shodan;
  if (s) {
    lines.push("", "Exposed services (Shodan InternetDB; existing public scan data, we did not scan the server):");
    if (!s.hosts.length) lines.push("  No Shodan records for this server.");
    for (const h of s.hosts) {
      lines.push(
        `  ${h.ip}: ports ${h.ports.map((p) => `${p.port} ${p.label}${p.highRisk ? " [HIGH RISK]" : ""}`).join(", ") || "none"}`,
      );
      if (h.cveTotal)
        lines.push(`    Known CVEs (${h.cveTotal}): ${h.cves.join(", ")}${h.cveTotal > h.cves.length ? ", …" : ""}`);
      if (h.cpes.length) lines.push(`    Software: ${h.cpes.join(", ")}`);
    }
  }
  const b = intel.breaches;
  if (b) {
    lines.push("", "Past data breaches (Have I Been Pwned; context only, not graded):");
    if (!b.breaches.length) lines.push("  No known public breaches for this domain.");
    for (const x of b.breaches) {
      lines.push(
        `  ${x.title} (${x.date ?? "date unknown"}): ${x.pwnCount.toLocaleString("en-US")} accounts, ${x.verified ? "verified" : "unverified"}; ${x.dataClasses.join(", ")}`,
      );
    }
  }
  const r = intel.rdap;
  if (r) {
    const age = domainAgeDays(r.registered);
    lines.push("", "Domain registration (RDAP):");
    if (age !== null) lines.push(`  ${humanAge(age)} (registered ${day(r.registered!)})`);
    if (r.expires) lines.push(`  Expires: ${day(r.expires)}`);
    if (r.registrar) lines.push(`  Registrar: ${r.registrar}`);
    for (const w of rdapWarnings(r)) lines.push(`  ! ${w.text}`);
  }
  const w = intel.wayback;
  if (w) {
    lines.push("", "Site history (Wayback Machine):");
    if (w.firstTimestamp) {
      lines.push(
        `  First seen: ${day(timestampToDate(w.firstTimestamp).toISOString())} (${snapshotUrl(w.firstTimestamp, w.domain)})`,
      );
      if (w.lastTimestamp) lines.push(`  Latest snapshot: ${day(timestampToDate(w.lastTimestamp).toISOString())}`);
      if (w.captures) lines.push(`  About ${w.captures.toLocaleString("en-US")} snapshots`);
    } else lines.push("  Not archived yet.");
  }
  const g = intel.geo;
  if (g) {
    lines.push("", "Server location (ipwho.is, approximate):");
    lines.push(
      `  ${[g.city, g.region, g.country].filter(Boolean).join(", ") || "unknown"} · ${g.ip}${g.asn ? ` · AS${g.asn}` : ""}${g.org ? ` ${g.org}` : ""}`,
    );
  }
  return lines.length ? ["", "HACKER'S VIEW (public data sources)", ...lines] : [];
}

/** Plain-text version of a report for the "Copy report" button. */
export function reportToText(report: ScanReport, siteName: string, intel: IntelState = {}): string {
  const lines: string[] = [];
  const date = new Date(report.scannedAt).toUTCString();
  lines.push(`${siteName} security report: ${report.domain}`);
  lines.push(`Grade: ${report.grade} (${report.score}/100)`);
  lines.push(`Scanned: ${date}`);
  if (report.finalUrl) lines.push(`Analysed URL: ${report.finalUrl}`);
  lines.push(`Results: ${report.counts.pass} passed, ${report.counts.warn} warnings, ${report.counts.fail} failed`);
  if (report.cap) lines.push(`Grade capped at ${report.cap.grade}: ${report.cap.reason}`);
  for (const p of report.penalties) lines.push(`Penalty ${p.points}: ${p.label}. ${p.reason}`);
  for (const note of report.notes) lines.push(`Note: ${note}`);

  for (const c of report.categories) {
    lines.push("", `${c.title.toUpperCase()}: ${c.score}/${c.maxScore}`);
    for (const f of c.findings) {
      lines.push(`  ${MARK[f.status]} ${f.title}: ${f.summary}`);
      if (f.fix && f.status !== "pass") lines.push(`      Fix: ${f.fix.replace(/`/g, "")}`);
    }
  }
  lines.push(...intelLines(intel));
  return lines.join("\n");
}
