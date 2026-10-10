import { describe, expect, it } from "vitest";
import { caaFinding, dnssecFinding } from "@/lib/scanner/checks/dns";
import {
  isSensitivePath,
  parseRobots,
  parseSecurityTxt,
  plainTextBody,
  robotsFinding,
  securityTxtFinding,
} from "@/lib/scanner/checks/files";
import { detectTechnologies } from "@/lib/scanner/checks/tech";
import {
  DNS_TYPES,
  dnssecStatus,
  encodeQuery,
  findZone,
  parseResponse,
  readName,
  type DnsResponse,
} from "@/lib/scanner/dnsraw";
import type { ChainResult, Hop } from "@/lib/scanner/net";

function hop(headers: Record<string, string | string[]>, extra: Partial<Hop> = {}): Hop {
  const h: Record<string, string[]> = {};
  for (const [k, v] of Object.entries(headers)) h[k.toLowerCase()] = Array.isArray(v) ? v : [v];
  return { url: "https://example.com/", status: 200, headers: h, tlsError: null, ...extra };
}
const chain = (h: Hop): ChainResult => ({ hops: [h], error: null, errorCode: null, stoppedReason: null });

describe("security.txt", () => {
  const now = new Date("2026-06-01T00:00:00Z");
  it("parses fields and ignores comments", () => {
    const p = parseSecurityTxt(
      "# hi\nContact: mailto:sec@example.com\nContact: https://example.com/report\nExpires: 2027-01-01T00:00:00Z\n",
    );
    expect(p.contact).toEqual(["mailto:sec@example.com", "https://example.com/report"]);
    expect(p.expires).toBe("2027-01-01T00:00:00Z");
  });
  it("passes a complete, current file", () => {
    const f = securityTxtFinding({ body: "Contact: mailto:a@b.com\nExpires: 2027-01-01T00:00:00Z", reason: "" }, now);
    expect(f.status).toBe("pass");
    expect(f.points).toBe(3);
  });
  it("warns when expired or incomplete", () => {
    expect(
      securityTxtFinding({ body: "Contact: mailto:a@b.com\nExpires: 2025-01-01T00:00:00Z", reason: "" }, now).summary,
    ).toMatch(/expired/);
    expect(securityTxtFinding({ body: "Contact: mailto:a@b.com", reason: "" }, now).summary).toMatch(/no Expires/);
    expect(securityTxtFinding({ body: "Expires: 2027-01-01T00:00:00Z", reason: "" }, now).summary).toMatch(
      /no Contact/,
    );
  });
  it("warns when missing", () => {
    const f = securityTxtFinding({ body: null, reason: "HTTP 404" }, now);
    expect(f.status).toBe("warn");
    expect(f.points).toBe(0);
  });
});

describe("plain text responses", () => {
  it("accepts text/plain 200", () => {
    expect(plainTextBody(chain(hop({ "content-type": "text/plain; charset=utf-8" }, { body: "x" }))).body).toBe("x");
  });
  it("rejects HTML soft-404s, errors and oversized files", () => {
    expect(plainTextBody(chain(hop({ "content-type": "text/html" }, { body: "<html>" }))).body).toBeNull();
    expect(plainTextBody(chain(hop({ "content-type": "text/plain" }, { status: 404 }))).body).toBeNull();
    expect(plainTextBody(chain(hop({ "content-type": "text/plain" }, { bodyTooLarge: true }))).reason).toMatch(
      /size limit/,
    );
  });
});

describe("robots.txt", () => {
  const text = `User-agent: *
Disallow: /admin/
Disallow: /search   # crawl budget
Disallow: /backup.zip
Disallow: /wp-admin/
Disallow: /.git/
Disallow: /staging/
Allow: /public/
User-agent: Googlebot
Disallow: /config.php
Disallow: /admin/`;
  it("lists Disallow paths and highlights sensitive ones", () => {
    const r = parseRobots(text);
    expect(r.total).toBe(7);
    expect(r.sensitive).toEqual(["/admin/", "/backup.zip", "/.git/", "/staging/", "/config.php"]);
    expect(r.disallow).toContain("/search");
  });
  it("doesn't flag ordinary or well-known paths", () => {
    for (const p of ["/search", "/cart", "/wp-admin/", "/administration-guide-pdf"])
      expect(isSensitivePath(p)).toBe(false);
    expect(isSensitivePath("/.env")).toBe(true);
    expect(isSensitivePath("/db/")).toBe(true);
  });
  it("is informational: never affects the score", () => {
    const r = robotsFinding({ body: text, reason: "" });
    expect(r.finding.status).toBe("warn");
    expect(r.finding.maxPoints).toBe(0);
    expect(robotsFinding({ body: null, reason: "HTTP 404" }).finding.status).toBe("info");
  });
});

describe("technology detection", () => {
  it("detects technologies and versions from headers and cookie names", () => {
    const techs = detectTechnologies([
      hop({
        server: "Apache/2.4.41 (Ubuntu)",
        "x-powered-by": "PHP/8.1.2",
        "cf-ray": "abc",
        link: '<https://example.com/wp-json/>; rel="https://api.w.org/"',
        "set-cookie": ["PHPSESSID=SECRETVALUE; path=/", "wordpress_test_cookie=WP; path=/"],
      }),
    ]);
    const byName = Object.fromEntries(techs.map((t) => [t.name, t]));
    expect(byName.Apache.version).toBe("2.4.41");
    expect(byName.PHP.version).toBe("8.1.2");
    expect(byName.Cloudflare).toBeDefined();
    expect(byName.WordPress).toBeDefined();
    expect(JSON.stringify(techs)).not.toContain("SECRETVALUE");
  });
  it("does not take another product's version", () => {
    const techs = detectTechnologies([hop({ server: "Apache PHP/7.4" })]);
    expect(techs.find((t) => t.name === "Apache")?.version).toBeNull();
  });
  it("detects frameworks from cookie names only", () => {
    const techs = detectTechnologies([hop({ "set-cookie": ["laravel_session=x", "ASP.NET_SessionId=y"] })]);
    expect(techs.map((t) => t.name).sort()).toEqual(["ASP.NET", "Laravel"]);
  });
});

describe("raw DNS", () => {
  it("encodes a DS query with EDNS0 and the DO bit", () => {
    const q = encodeQuery("example.com", DNS_TYPES.DS, 0x1234);
    expect(q.readUInt16BE(0)).toBe(0x1234);
    expect(q.readUInt16BE(4)).toBe(1);
    expect(q.readUInt16BE(10)).toBe(1);
    expect(q.subarray(12, 25).toString("latin1")).toBe("\x07example\x03com\x00");
    expect(q.readUInt16BE(25)).toBe(43);
    expect(q.at(-4)).toBe(0x80); // DO bit
  });

  it("parses answers and compressed names", () => {
    // Response for "example.com DS" with one DS answer using a compression pointer to the question name.
    const header = Buffer.from([0x12, 0x34, 0x81, 0xa0, 0, 1, 0, 1, 0, 0, 0, 0]);
    const question = Buffer.concat([Buffer.from("\x07example\x03com\x00", "latin1"), Buffer.from([0, 43, 0, 1])]);
    const answer = Buffer.from([0xc0, 12, 0, 43, 0, 1, 0, 0, 0x0e, 0x10, 0, 4, 1, 2, 3, 4]);
    const res = parseResponse(Buffer.concat([header, question, answer]));
    expect(res.id).toBe(0x1234);
    expect(res.ad).toBe(true);
    expect(res.answers).toEqual([{ name: "example.com", type: 43 }]);
  });

  it("rejects pointer loops and truncated packets", () => {
    const loop = Buffer.from([0xc0, 0]);
    expect(() => readName(loop, 0)).toThrow();
    expect(() => parseResponse(Buffer.from([1, 2, 3]))).toThrow();
  });

  const fake =
    (zones: Record<string, { signed: boolean }>, cnames: string[] = []) =>
    async (name: string, type: number): Promise<DnsResponse> => {
      const base = { id: 1, rcode: 0, ad: false, truncated: false, answers: [], authority: [] } as DnsResponse;
      const zone = Object.keys(zones).find((z) => name === z || name.endsWith(`.${z}`));
      if (type === DNS_TYPES.SOA) {
        if (cnames.includes(name)) return { ...base, answers: [{ name, type: DNS_TYPES.CNAME }] };
        if (zone === name) return { ...base, answers: [{ name, type: DNS_TYPES.SOA }] };
        return { ...base, authority: zone ? [{ name: zone, type: DNS_TYPES.SOA }] : [] };
      }
      if (type === DNS_TYPES.DS && zone === name && zones[zone].signed)
        return { ...base, answers: [{ name, type: DNS_TYPES.DS }] };
      return base;
    };

  it("finds the zone apex, skipping CNAMEs and respecting multi-label suffixes", async () => {
    const q = fake({ "example.co.uk": { signed: true }, "co.uk": { signed: true } }, ["www.example.co.uk"]);
    expect(await findZone("www.example.co.uk", q)).toBe("example.co.uk");
    expect(await findZone("deep.sub.example.co.uk", q)).toBe("example.co.uk");
  });

  it("reports signed and unsigned zones", async () => {
    expect((await dnssecStatus("www.signed.com", fake({ "signed.com": { signed: true } }))).status).toBe("signed");
    // An unsigned zone under a signed suffix must not be reported as signed.
    const q = fake({ "plain.co.uk": { signed: false }, "co.uk": { signed: true } });
    expect((await dnssecStatus("plain.co.uk", q)).status).toBe("unsigned");
  });

  it("returns unknown on resolver errors", async () => {
    const failing = async () => {
      throw new Error("timeout");
    };
    expect((await dnssecStatus("example.com", failing)).status).toBe("unknown");
  });
});

describe("DNS findings", () => {
  it("scores CAA", () => {
    expect(caaFinding("example.com", { records: [], foundAt: null, error: null }).status).toBe("warn");
    const ok = caaFinding("www.example.com", {
      records: [{ tag: "issue", value: "letsencrypt.org" }],
      foundAt: "example.com",
      error: null,
    });
    expect(ok.status).toBe("pass");
    expect(ok.summary).toMatch(/letsencrypt\.org.*inherited from example\.com/);
  });
  it("scores DNSSEC", () => {
    expect(dnssecFinding({ status: "signed", zone: "example.com", validated: true }).points).toBe(3);
    expect(dnssecFinding({ status: "unsigned", zone: "example.com", validated: false }).points).toBe(0);
    expect(dnssecFinding({ status: "unknown", zone: null, validated: false }).status).toBe("warn");
  });
});
