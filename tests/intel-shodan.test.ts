import { describe, expect, it } from "vitest";
import { cached, clearIntelCache, FAILURE_TTL_MS } from "@/lib/intel/cache";
import { CVE_DISPLAY_LIMIT, describePort, exposurePenalties, parseInternetDb } from "@/lib/intel/shodan";
import type { ShodanHost, ShodanIntel } from "@/lib/intel/types";
import { computeGrade } from "@/lib/scanner/scoring";
import type { CategoryResult } from "@/lib/scanner/types";

const IP = "203.0.114.10";

describe("Shodan InternetDB parsing", () => {
  it("parses ports, CVEs, CPEs, tags and hostnames", () => {
    const host = parseInternetDb(
      {
        ip: IP,
        ports: [443, 22, 3306, 80, 22],
        vulns: ["CVE-2019-0001", "CVE-2023-12345", "CVE-2021-44228"],
        cpes: ["cpe:/a:nginx:nginx:1.18.0", "cpe:/o:canonical:ubuntu_linux"],
        tags: ["cloud"],
        hostnames: ["example.com"],
      },
      IP,
    );
    expect(host.ports.map((p) => p.port)).toEqual([22, 80, 443, 3306]);
    expect(host.ports.find((p) => p.port === 3306)).toMatchObject({
      label: "MySQL / MariaDB",
      kind: "database",
      highRisk: true,
    });
    expect(host.ports.find((p) => p.port === 443)?.highRisk).toBe(false);
    expect(host.cves).toEqual(["CVE-2023-12345", "CVE-2021-44228", "CVE-2019-0001"]); // newest first
    expect(host.cpes).toHaveLength(2);
  });

  it("drops invalid and hostile values", () => {
    const host = parseInternetDb(
      {
        ip: IP,
        ports: [0, 70000, -1, "22", 8080.5, 443],
        vulns: ["CVE-2021-1", "<img src=x onerror=alert(1)>", "javascript:alert(1)", "CVE-2022-0001"],
        cpes: ['cpe:/a:x:y"><script>', "not-a-cpe"],
        tags: ["<b>bold</b>", "ok-tag"],
        hostnames: ["evil<script>.com", "fine.example.org"],
      },
      IP,
    );
    expect(host.ports.map((p) => p.port)).toEqual([443]);
    expect(host.cves).toEqual(["CVE-2022-0001"]);
    expect(host.cpes).toEqual([]);
    expect(host.tags).toEqual(["ok-tag"]);
    expect(host.hostnames).toEqual(["fine.example.org"]);
  });

  it("caps the CVE list but keeps the real total", () => {
    const vulns = Array.from({ length: 40 }, (_, i) => `CVE-2020-${String(1000 + i)}`);
    const host = parseInternetDb({ ip: IP, ports: [], vulns }, IP);
    expect(host.cves).toHaveLength(CVE_DISPLAY_LIMIT);
    expect(host.cveTotal).toBe(40);
  });

  it("rejects responses for another IP or with the wrong shape", () => {
    expect(() => parseInternetDb({ ip: "1.1.1.1", ports: [] }, IP)).toThrow();
    expect(() => parseInternetDb([], IP)).toThrow();
    expect(() => parseInternetDb("oops", IP)).toThrow();
  });

  it("never flags a CDN edge's ports as the site's exposed services", () => {
    const cf = parseInternetDb(
      { ip: IP, ports: [80, 443, 2082, 2083, 2086, 2087, 8443, 3306], tags: ["cdn"], vulns: ["CVE-2020-0001"] },
      IP,
    );
    expect(cf.ports.some((p) => p.highRisk)).toBe(false);
    expect(cf.ports.find((p) => p.port === 2083)?.label).toBe("CDN proxy port (HTTPS)");
    expect(exposurePenalties({ hosts: [cf], noData: [] })).toEqual([]);
  });

  it("labels well-known ports", () => {
    expect(describePort(6379)).toMatchObject({ label: "Redis", highRisk: true });
    expect(describePort(3389)).toMatchObject({ kind: "remote-admin", highRisk: true });
    expect(describePort(12345)).toMatchObject({ label: "Unknown service", highRisk: false });
  });
});

const host = (ports: number[], cveTotal = 0): ShodanHost => ({
  ip: IP,
  ports: ports.map(describePort),
  cves: [],
  cveTotal,
  cpes: [],
  tags: [],
  hostnames: [],
});
const intel = (...hosts: ShodanHost[]): ShodanIntel => ({ hosts, noData: [] });
const fullMarks: CategoryResult = {
  id: "headers",
  title: "",
  description: "",
  score: 100,
  maxScore: 100,
  status: "pass",
  findings: [],
};

describe("exposure penalties", () => {
  it("are empty for web-only servers or missing data", () => {
    expect(exposurePenalties(intel(host([80, 443])))).toEqual([]);
    expect(exposurePenalties(null)).toEqual([]);
  });

  it("deduct for databases and remote admin, and cap the grade at C for databases", () => {
    const p = exposurePenalties(intel(host([22, 443, 6379])));
    expect(p[0].points).toBe(-8); // Redis 5 + SSH 3
    expect(p[0].capsGrade).toBe("C");
    const r = computeGrade([fullMarks], p);
    expect(r.score).toBe(92);
    expect(r.grade).toBe("C");
  });

  it("don't cap the grade for remote admin only, but rule out A+", () => {
    const p = exposurePenalties(intel(host([22, 443])));
    expect(p[0].points).toBe(-3);
    expect(p[0].capsGrade).toBeUndefined();
    expect(computeGrade([fullMarks], p).grade).toBe("A");
  });

  it("deduct for CVEs and respect the caps", () => {
    expect(exposurePenalties(intel(host([443], 2)))[0].points).toBe(-3);
    expect(exposurePenalties(intel(host([443], 9)))[0].points).toBe(-6);
    const worst = exposurePenalties(intel(host([3306, 5432, 6379, 27017, 22, 3389], 50)));
    expect(worst.reduce((s, p) => s + p.points, 0)).toBe(-15);
    expect(worst[0].points).toBe(-12);
  });

  it("never push the score below zero", () => {
    const zero = { ...fullMarks, score: 5 };
    expect(computeGrade([zero], exposurePenalties(intel(host([3306], 9)))).score).toBe(0);
  });
});

describe("intel cache", () => {
  it("caches results and shares in-flight requests", async () => {
    clearIntelCache();
    let calls = 0;
    const load = async () => {
      calls++;
      return "value";
    };
    const [a, b] = await Promise.all([cached("k", 1000, load), cached("k", 1000, load)]);
    expect([a, b, calls]).toEqual(["value", "value", 1]);
    expect(await cached("k", 1000, load)).toBe("value");
    expect(calls).toBe(1);
  });

  it("expires entries and caches failures only briefly", async () => {
    clearIntelCache();
    let now = 0;
    const clock = () => now;
    let calls = 0;
    const failing = async () => {
      calls++;
      throw new Error("429");
    };
    expect(await cached("f", 24 * 3600e3, failing, clock)).toBeNull();
    now = FAILURE_TTL_MS - 1;
    await cached("f", 24 * 3600e3, failing, clock);
    expect(calls).toBe(1);
    now = FAILURE_TTL_MS + 1;
    await cached("f", 24 * 3600e3, failing, clock);
    expect(calls).toBe(2);
  });
});
