import { describe, expect, it } from "vitest";
import {
  buildFixes,
  caaIssuerFor,
  fixedSpf,
  securityTxtContent,
  STARTER_CSP,
  type FindingFix,
  type Platform,
} from "@/lib/fixes";
import type { Finding, ScanReport, Status } from "@/lib/scanner/types";

function f(id: string, status: Status, extra: Partial<Finding> = {}): Finding {
  return { id, title: id, status, points: 0, maxPoints: 1, summary: "", explanation: "", ...extra };
}

function report(findings: Finding[], extra: Partial<ScanReport["details"]> = {}): ScanReport {
  return {
    domain: "www.example.com",
    scannedAt: "2026-01-01T00:00:00Z",
    durationMs: 1,
    finalUrl: "https://www.example.com/",
    finalStatus: 200,
    ip: null,
    score: 50,
    grade: "C",
    cap: null,
    counts: { pass: 0, warn: 0, fail: 0 },
    categories: [{ id: "headers", title: "", description: "", score: 0, maxScore: 0, status: "fail", findings }],
    penalties: [],
    details: {
      tls: null,
      technologies: [],
      robots: { found: false, disallow: [], sensitive: [], total: 0 },
      email: { domain: "example.com", spfRecord: null },
      frame: { frameable: false, url: null },
      ...extra,
    },
    notes: [],
  };
}

const code = (fix: FindingFix | undefined, platform: Platform) =>
  fix?.kind === "platform" ? fix.byPlatform[platform].snippets.map((s) => s.code).join("\n") : "";

describe("fix generator", () => {
  it("returns nothing when every check passes", () => {
    const b = buildFixes(report([f("hsts", "pass"), f("csp", "pass")]));
    expect(b.hasAny).toBe(false);
    expect(b.combined.nginx.snippets).toHaveLength(0);
  });

  it("only includes the headers that are actually missing", () => {
    const b = buildFixes(report([f("hsts", "pass"), f("csp", "fail"), f("x-content-type-options", "fail")]));
    const nginx = b.combined.nginx.snippets[0].code;
    expect(nginx).toContain(`add_header Content-Security-Policy "${STARTER_CSP}" always;`);
    expect(nginx).toContain('add_header X-Content-Type-Options "nosniff" always;');
    expect(nginx).not.toContain("Strict-Transport-Security");
    expect(code(b.byFinding["x-content-type-options"], "nginx")).not.toContain("Content-Security-Policy");
  });

  it("attaches the test-before-enforcing warning to the starter CSP", () => {
    const b = buildFixes(report([f("csp", "fail")]));
    expect(b.byFinding.csp.warning).toMatch(/Report-Only/);
    expect(b.combinedWarning).toMatch(/Report-Only/);
    expect(buildFixes(report([f("hsts", "fail")])).combinedWarning).toBeUndefined();
  });

  it("produces valid vercel.json", () => {
    const b = buildFixes(report([f("hsts", "fail"), f("x-frame-options", "fail")]));
    const json = JSON.parse(b.combined.vercel.snippets[0].code);
    expect(json.headers[0].source).toBe("/(.*)");
    expect(json.headers[0].headers).toEqual([
      { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
      { key: "X-Frame-Options", value: "SAMEORIGIN" },
    ]);
  });

  it("produces Netlify _headers, Apache, Cloudflare and Next.js config", () => {
    const b = buildFixes(
      report([f("x-content-type-options", "fail"), f("powered-by", "warn", { evidence: "x-powered-by: Express" })]),
    );
    expect(b.combined.netlify.snippets[0].code).toBe("/*\n  X-Content-Type-Options: nosniff");
    const apache = b.combined.apache.snippets[0].code;
    expect(apache).toContain('Header always set X-Content-Type-Options "nosniff"');
    expect(apache).toContain("Header always unset X-Powered-By");
    expect(b.combined.cloudflare.snippets[0].code).toContain("Set static   X-Content-Type-Options   =   nosniff");
    expect(b.combined.cloudflare.snippets[0].code).toContain("Remove       X-Powered-By");
    const next = b.combined.nextjs.snippets[0].code;
    expect(next).toContain("poweredByHeader: false");
    expect(next).toContain('{ key: "X-Content-Type-Options", value: "nosniff" }');
  });

  it("removes exactly the leaking headers that were seen", () => {
    const b = buildFixes(
      report([f("powered-by", "fail", { evidence: "x-powered-by: PHP/8.1\nx-aspnet-version: 4.0.30319" })]),
    );
    const nginx = b.combined.nginx.snippets[0].code;
    expect(nginx).toContain("fastcgi_hide_header X-Powered-By;");
    expect(nginx).toContain("proxy_hide_header X-AspNet-Version;");
    expect(nginx).not.toContain("X-Generator");
  });

  it("generates the redirect, server_tokens, TLS and cookie fixes", () => {
    const b = buildFixes(
      report([
        f("http-redirect", "fail"),
        f("server-header", "fail"),
        f("tls-protocols", "fail", { summary: "Still accepts TLS 1.0." }),
        f("cookie-secure", "warn"),
        f("cookie-samesite", "warn"),
      ]),
    );
    const nginx = b.combined.nginx.snippets[0].code;
    expect(nginx).toContain("return 301 https://$host$request_uri;");
    expect(nginx).toContain("server_name example.com www.example.com;");
    expect(nginx).toContain("server_tokens off;");
    expect(nginx).toContain("ssl_protocols TLSv1.2 TLSv1.3;");
    expect(nginx).toContain("proxy_cookie_flags ~ secure samesite=lax;");
    expect(nginx).not.toContain("httponly");
    const apacheServer = b.combined.apache.snippets.find((s) => s.filename.includes("httpd.conf"))!.code;
    expect(apacheServer).toContain("ServerTokens Prod");
    expect(apacheServer).toContain("SSLProtocol -all +TLSv1.2 +TLSv1.3");
    expect(b.combined.cloudflare.snippets[0].code).toContain("Minimum TLS Version → TLS 1.2");
  });

  it("doesn't recommend TLS changes when support was merely unknown", () => {
    const b = buildFixes(
      report([f("tls-protocols", "warn", { summary: "Could not confirm support for TLS 1.2 or 1.3." })]),
    );
    expect(b.byFinding["tls-protocols"]).toBeUndefined();
  });

  it("generates a security.txt that expires in a year", () => {
    const text = securityTxtContent("www.example.com", "example.com", new Date("2026-03-15T12:00:00Z"));
    expect(text).toContain("Contact: mailto:security@example.com");
    expect(text).toContain("Expires: 2027-03-15T00:00:00Z");
    const b = buildFixes(report([f("security-txt", "warn")]));
    const vercel = b.byFinding["security-txt"];
    expect(vercel.kind === "platform" && vercel.byPlatform.vercel.snippets[0].filename).toBe(
      "public/.well-known/security.txt",
    );
  });

  it("tailors DNS records", () => {
    expect(fixedSpf("v=spf1 include:_spf.google.com ?all")).toBe("v=spf1 include:_spf.google.com -all");
    expect(fixedSpf("v=spf1 include:_spf.google.com")).toBe("v=spf1 include:_spf.google.com -all");
    expect(fixedSpf("v=spf1 +all")).toBe("v=spf1 -all");
    expect(fixedSpf("v=spf1 redirect=_spf.example.net")).toBeNull();
    expect(caaIssuerFor("Let's Encrypt")).toBe("letsencrypt.org");
    expect(caaIssuerFor("Google Trust Services")).toBe("pki.goog");

    const b = buildFixes(
      report(
        [
          f("spf", "warn"),
          f("dmarc", "warn", { evidence: "_dmarc.example.com: v=DMARC1; p=none; rua=mailto:x@example.com" }),
          f("caa", "warn"),
        ],
        {
          email: { domain: "example.com", spfRecord: "v=spf1 include:mail.example.net ?all" },
          tls: {
            protocols: [],
            negotiated: null,
            cipher: null,
            keyExchange: null,
            key: null,
            signatureAlgorithm: null,
            issuerOrg: "Let's Encrypt",
            chain: [],
            sans: [],
            sanTotal: 0,
          },
        },
      ),
    );
    const dns = b.dns.snippets[0].code;
    expect(dns).toContain('example.com.  TXT  "v=spf1 include:mail.example.net -all"');
    expect(dns).toContain('_dmarc.example.com.  TXT  "v=DMARC1; p=quarantine; rua=mailto:x@example.com"');
    expect(dns).toContain('example.com.  CAA  0 issue "letsencrypt.org"');
  });
});

describe("cookie notes", () => {
  it("only mention the flags that are missing", () => {
    const b = buildFixes(report([f("cookie-httponly", "warn")]));
    const note = b.combined.vercel.notes.join(" ");
    expect(note).toContain("{ httpOnly: true }");
    expect(note).not.toContain("secure: true");
  });
});
