import { describe, expect, it } from "vitest";
import { checkCookies, parseSetCookie } from "@/lib/scanner/checks/cookies";
import { checkHeaders, parseCsp } from "@/lib/scanner/checks/headers";
import { checkLeakage } from "@/lib/scanner/checks/leakage";
import type { Hop } from "@/lib/scanner/net";
import { computeGrade, gradeForScore } from "@/lib/scanner/scoring";
import type { CategoryResult } from "@/lib/scanner/types";

function hop(headers: Record<string, string | string[]>, url = "https://example.com/"): Hop {
  const h: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = Array.isArray(v) ? v : [v];
  return { url, status: 200, headers: h, tlsError: null };
}

const find = (c: CategoryResult, id: string) => c.findings.find((f) => f.id === id)!;

describe("security headers", () => {
  const strong = hop({
    "strict-transport-security": "max-age=63072000; includeSubDomains; preload",
    "content-security-policy":
      "default-src 'self'; script-src 'self' 'nonce-abc' 'strict-dynamic'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "strict-origin-when-cross-origin",
    "permissions-policy": "camera=()",
  });

  it("gives full marks to a strong configuration", () => {
    const c = checkHeaders(strong);
    expect(c.score).toBe(32);
    // frame-ancestors substitutes for X-Frame-Options
    expect(find(c, "x-frame-options").status).toBe("pass");
  });

  it("fails everything when headers are missing", () => {
    const c = checkHeaders(hop({}));
    expect(find(c, "hsts").status).toBe("fail");
    expect(find(c, "csp").status).toBe("fail");
    expect(find(c, "x-frame-options").status).toBe("fail");
    expect(find(c, "x-content-type-options").status).toBe("fail");
    expect(c.score).toBe(1); // only the partial Referrer-Policy credit
  });

  it("flags weak HSTS", () => {
    expect(find(checkHeaders(hop({ "strict-transport-security": "max-age=0" })), "hsts").status).toBe("fail");
    expect(find(checkHeaders(hop({ "strict-transport-security": "max-age=86400" })), "hsts").status).toBe("warn");
    expect(find(checkHeaders(hop({ "strict-transport-security": "includeSubDomains" })), "hsts").status).toBe("fail");
  });

  it("does not credit HSTS on plain HTTP", () => {
    const c = checkHeaders(hop({ "strict-transport-security": "max-age=63072000" }, "http://example.com/"));
    expect(find(c, "hsts").points).toBe(0);
  });

  it("penalises unsafe CSP", () => {
    const unsafe = find(
      checkHeaders(hop({ "content-security-policy": "default-src * 'unsafe-inline' 'unsafe-eval'" })),
      "csp",
    );
    expect(unsafe.status).toBe("warn");
    expect(unsafe.points).toBeLessThan(5);
    const reportOnly = find(checkHeaders(hop({ "content-security-policy-report-only": "default-src 'self'" })), "csp");
    expect(reportOnly.status).toBe("warn");
    // 'unsafe-inline' is ignored by browsers when a nonce is present
    const nonce = find(
      checkHeaders(hop({ "content-security-policy": "script-src 'self' 'unsafe-inline' 'nonce-x'" })),
      "csp",
    );
    expect(nonce.status).toBe("pass");
    const noScripts = find(checkHeaders(hop({ "content-security-policy": "upgrade-insecure-requests" })), "csp");
    expect(noScripts.status).toBe("warn");
  });

  it("parses multiple CSP policies", () => {
    expect(parseCsp("default-src 'self', frame-ancestors 'none'")).toHaveLength(2);
  });

  it("uses the last recognised Referrer-Policy", () => {
    const c = checkHeaders(hop({ "referrer-policy": "unsafe-url, strict-origin-when-cross-origin" }));
    expect(find(c, "referrer-policy").status).toBe("pass");
    expect(find(checkHeaders(hop({ "referrer-policy": "unsafe-url" })), "referrer-policy").status).toBe("fail");
  });
});

describe("information leakage", () => {
  it("flags versioned Server and X-Powered-By headers", () => {
    const c = checkLeakage(hop({ server: "nginx/1.18.0 (Ubuntu)", "x-powered-by": "PHP/8.1.2" }), []);
    expect(c.score).toBe(0);
  });
  it("accepts version-less headers", () => {
    expect(checkLeakage(hop({ server: "cloudflare" }), []).score).toBe(5);
    expect(find(checkLeakage(hop({ "x-powered-by": "Express" }), []), "powered-by").status).toBe("warn");
  });
});

describe("cookies", () => {
  it("parses flags without keeping values", () => {
    expect(parseSetCookie("sid=SECRET; Path=/; Secure; HttpOnly; SameSite=Lax")).toEqual({
      name: "sid",
      secure: true,
      httpOnly: true,
      sameSite: "lax",
    });
  });

  it("never includes cookie values in the report", () => {
    const c = checkCookies([hop({ "set-cookie": ["session=TOPSECRETVALUE; Path=/"] })]);
    expect(JSON.stringify(c)).not.toContain("TOPSECRETVALUE");
    expect(find(c, "cookie-secure").status).toBe("fail");
  });

  it("gives full marks when no cookies are set", () => {
    expect(checkCookies([hop({})]).score).toBe(8);
  });

  it("treats SameSite=None without Secure as invalid", () => {
    const c = checkCookies([hop({ "set-cookie": ["a=1; HttpOnly; SameSite=None"] })]);
    expect(find(c, "cookie-samesite").status).toBe("warn");
  });
});

describe("grading", () => {
  it("maps scores to grades", () => {
    expect(gradeForScore(100)).toBe("A+");
    expect(gradeForScore(90)).toBe("A");
    expect(gradeForScore(72)).toBe("B");
    expect(gradeForScore(60)).toBe("C");
    expect(gradeForScore(45)).toBe("D");
    expect(gradeForScore(10)).toBe("F");
  });

  const cat = (id: string, status: "pass" | "fail", points: number): CategoryResult => ({
    id: "tls",
    title: "",
    description: "",
    score: points,
    maxScore: points,
    status,
    findings: [{ id, title: "", status, points, maxPoints: points, summary: "", explanation: "" }],
  });

  it("caps the grade when the certificate is invalid", () => {
    const r = computeGrade([cat("other", "pass", 90), cat("tls-valid", "fail", 0)]);
    expect(r.score).toBe(90);
    expect(r.grade).toBe("D");
    expect(r.cap?.grade).toBe("D");
  });

  it("reserves A+ for scans without failures", () => {
    expect(computeGrade([cat("other", "pass", 97), cat("x", "fail", 0)]).grade).toBe("A");
    expect(computeGrade([cat("other", "pass", 97)]).grade).toBe("A+");
  });
});
