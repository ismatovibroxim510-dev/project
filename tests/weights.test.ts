import { describe, expect, it } from "vitest";
import { checkCookies } from "@/lib/scanner/checks/cookies";
import { caaFinding, dnssecFinding } from "@/lib/scanner/checks/dns";
import { robotsFinding, securityTxtFinding } from "@/lib/scanner/checks/files";
import { checkHeaders } from "@/lib/scanner/checks/headers";
import { checkHttps } from "@/lib/scanner/checks/https";
import { checkLeakage } from "@/lib/scanner/checks/leakage";
import { checkTls } from "@/lib/scanner/checks/tls";
import type { ChainResult, Hop } from "@/lib/scanner/net";
import { CATEGORY_META, type CategoryId, type Finding } from "@/lib/scanner/types";
import { CHECK_WEIGHTS } from "@/lib/scanner/weights";

const hop = (url: string, headers: Record<string, string[]> = {}): Hop => ({
  url,
  status: 200,
  headers,
  tlsError: null,
});
const chain = (h: Hop): ChainResult => ({ hops: [h], error: null, errorCode: null, stoppedReason: null });

describe("documented weights", () => {
  it("add up to 100 and match each category's maximum", () => {
    let total = 0;
    for (const [id, checks] of Object.entries(CHECK_WEIGHTS)) {
      const sum = checks.reduce((s, c) => s + c.points, 0);
      expect(sum).toBe(CATEGORY_META[id as CategoryId].maxScore);
      total += sum;
    }
    expect(total).toBe(100);
  });

  it("match what the checks actually award", () => {
    const h = hop("https://example.com/", { "set-cookie": ["a=1"] });
    const findings: Finding[] = [
      ...checkHttps(chain(h), chain(h)).findings,
      ...checkTls("example.com", { error: Object.assign(new Error("x"), { code: "ECONNREFUSED" }) }, []).category
        .findings,
      ...checkHeaders(h).findings,
      ...checkCookies([h]).findings,
      ...checkLeakage(h, []).findings,
      caaFinding("example.com", { records: [], foundAt: null, error: null }),
      dnssecFinding({ status: "unsigned", zone: "example.com", validated: false }),
      securityTxtFinding({ body: null, reason: "" }),
      robotsFinding({ body: null, reason: "" }).finding,
    ];
    for (const checks of Object.values(CHECK_WEIGHTS)) {
      for (const c of checks) {
        if (c.id === "spf" || c.id === "dmarc") continue; // need DNS; covered by checks.test.ts
        const f = findings.find((x) => x.id === c.id);
        expect(f, c.id).toBeDefined();
        expect(f!.maxPoints, c.id).toBe(c.points);
      }
    }
  });
});
