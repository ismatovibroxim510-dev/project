import { describe, expect, it } from "vitest";
import { reportToText } from "@/lib/report-text";
import type { IntelState } from "@/lib/intel/types";
import type { ScanReport } from "@/lib/scanner/types";

const report: ScanReport = {
  domain: "example.com",
  scannedAt: "2026-10-10T00:00:00Z",
  durationMs: 1,
  finalUrl: "https://example.com/",
  finalStatus: 200,
  ip: "203.0.114.1",
  score: 70,
  grade: "B",
  cap: null,
  counts: { pass: 1, warn: 0, fail: 0 },
  categories: [],
  penalties: [
    { id: "exposed-ports", label: "Exposed high-risk services", points: -5, reason: "Reachable: 3306 MySQL." },
  ],
  details: {
    tls: null,
    technologies: [],
    robots: { found: false, disallow: [], sensitive: [], total: 0 },
    email: { domain: "example.com", spfRecord: null },
    frame: { frameable: false, url: null },
  },
  notes: [],
};

const intel: IntelState = {
  shodan: {
    hosts: [
      {
        ip: "203.0.114.1",
        ports: [{ port: 3306, label: "MySQL / MariaDB", kind: "database", highRisk: true }],
        cves: ["CVE-2021-44228"],
        cveTotal: 1,
        cpes: [],
        tags: [],
        hostnames: [],
      },
    ],
    noData: [],
  },
  breaches: { domain: "example.com", breaches: [], total: 0 },
  rdap: {
    domain: "example.com",
    registered: "1995-08-14T04:00:00Z",
    expires: null,
    updated: null,
    registrar: "RESERVED-IANA",
  },
  wayback: { domain: "example.com", firstTimestamp: "20020120142510", lastTimestamp: null, captures: 1234 },
  geo: null,
};

describe("copy report text", () => {
  it("includes penalties and every available Hacker's View source", () => {
    const text = reportToText(report, "SiteGrade", intel);
    expect(text).toContain("Penalty -5: Exposed high-risk services");
    expect(text).toContain("3306 MySQL / MariaDB [HIGH RISK]");
    expect(text).toContain("CVE-2021-44228");
    expect(text).toContain("No known public breaches for this domain.");
    expect(text).toMatch(/\d+ years old \(registered 1995-08-14\)/);
    expect(text).toContain("https://web.archive.org/web/20020120142510/http://example.com/");
    expect(text).not.toContain("Server location"); // unavailable source omitted
  });

  it("omits the section entirely when no intel is available", () => {
    expect(reportToText(report, "SiteGrade")).not.toContain("HACKER'S VIEW");
  });
});
