import { describe, expect, it } from "vitest";
import { parseGeo } from "@/lib/intel/geo";
import { BREACH_DISPLAY_LIMIT, parseBreaches } from "@/lib/intel/hibp";
import { domainAgeDays, humanAge, parseRdap, rdapWarnings } from "@/lib/intel/rdap";
import { registrableDomain, stripHtml, text } from "@/lib/intel/sanitize";
import { parseCdxFirst, parseSparkline, snapshotUrl, timestampToDate } from "@/lib/intel/wayback";

describe("sanitizers", () => {
  it("strips HTML to plain text", () => {
    const html =
      'In 2013 <em>153 million</em> accounts &amp; hints were <a href="http://x" target="_blank">exposed</a>.<script>alert(1)</script><style>p{}</style>';
    expect(stripHtml(html)).toBe("In 2013 153 million accounts & hints were exposed .");
    expect(stripHtml("&lt;script&gt;alert(1)&lt;/script&gt;")).toBe("scriptalert(1)/script");
    expect(stripHtml('<img src=x onerror="alert(1)">hi')).toBe("hi");
    expect(stripHtml("&#60;b&#62;x &#x3C;i&#x3E;")).toBe("bx i");
    expect(stripHtml(42)).toBeNull();
  });

  it("caps and cleans text", () => {
    expect(text("a\u0000b‮c  d")).toBe("a b c d");
    expect(text("x".repeat(500), 10)).toHaveLength(10);
    expect(text({})).toBeNull();
  });

  it("approximates the registrable domain", () => {
    expect(registrableDomain("www.example.com")).toBe("example.com");
    expect(registrableDomain("a.b.example.co.uk")).toBe("example.co.uk");
    expect(registrableDomain("bbc.co.uk")).toBe("bbc.co.uk");
    expect(registrableDomain("example.io")).toBe("example.io");
  });
});

describe("Have I Been Pwned", () => {
  const breach = {
    Name: "Adobe",
    Title: "Adobe",
    BreachDate: "2013-10-04",
    PwnCount: 152445165,
    Description: 'Passwords were <a href="https://x">poorly encrypted</a>.',
    DataClasses: ["Email addresses", "Passwords"],
    IsVerified: true,
  };

  it("parses breaches and strips HTML from descriptions", () => {
    const r = parseBreaches([breach], "adobe.com");
    expect(r.total).toBe(1);
    expect(r.breaches[0]).toEqual({
      name: "Adobe",
      title: "Adobe",
      date: "2013-10-04",
      pwnCount: 152445165,
      dataClasses: ["Email addresses", "Passwords"],
      verified: true,
      description: "Passwords were poorly encrypted .",
    });
  });

  it("handles none, hostile and malformed entries", () => {
    expect(parseBreaches([], "example.com")).toEqual({ domain: "example.com", breaches: [], total: 0 });
    const r = parseBreaches(
      [
        { ...breach, Name: "<script>" },
        { ...breach, Name: "Fake", IsFabricated: true },
        { ...breach, Name: "Ok", BreachDate: "not-a-date", PwnCount: "lots", DataClasses: "x" },
        null,
        "str",
      ],
      "example.com",
    );
    expect(r.breaches.map((b) => b.name)).toEqual(["Ok"]);
    expect(r.breaches[0]).toMatchObject({ date: null, pwnCount: 0, dataClasses: [] });
    expect(() => parseBreaches({ error: 1 }, "example.com")).toThrow();
  });

  it("caps the list, newest first", () => {
    const many = Array.from({ length: 25 }, (_, i) => ({
      ...breach,
      Name: `B${i}`,
      BreachDate: `20${10 + (i % 10)}-01-01`,
    }));
    const r = parseBreaches(many, "example.com");
    expect(r.breaches).toHaveLength(BREACH_DISPLAY_LIMIT);
    expect(r.total).toBe(25);
    expect(r.breaches[0].date).toBe("2019-01-01");
  });
});

describe("RDAP", () => {
  const rdap = {
    objectClassName: "domain",
    events: [
      { eventAction: "registration", eventDate: "2007-10-09T18:20:50Z" },
      { eventAction: "expiration", eventDate: "2028-10-09T18:20:50Z" },
      { eventAction: "last changed", eventDate: "2026-09-07T09:22:52Z" },
    ],
    entities: [
      {
        roles: ["registrar"],
        vcardArray: [
          "vcard",
          [
            ["version", {}, "text", "4.0"],
            ["fn", {}, "text", "MarkMonitor Inc."],
          ],
        ],
      },
    ],
  };

  it("extracts dates and the registrar", () => {
    expect(parseRdap(rdap, "github.com")).toEqual({
      domain: "github.com",
      registered: "2007-10-09T18:20:50.000Z",
      expires: "2028-10-09T18:20:50.000Z",
      updated: "2026-09-07T09:22:52.000Z",
      registrar: "MarkMonitor Inc.",
    });
  });

  it("rejects junk", () => {
    expect(() => parseRdap({ objectClassName: "entity" }, "x.com")).toThrow();
    expect(() => parseRdap({ events: [{ eventAction: "registration", eventDate: "yesterday" }] }, "x.com")).toThrow();
    expect(() => parseRdap([], "x.com")).toThrow();
  });

  it("describes age and warns about new or expiring domains", () => {
    const now = new Date("2026-10-10T00:00:00Z");
    expect(humanAge(domainAgeDays("2007-10-09T00:00:00Z", now)!)).toBe("19 years old");
    expect(humanAge(10)).toBe("10 days old");
    expect(humanAge(200)).toBe("6 months old");
    const young = rdapWarnings(
      {
        domain: "x.com",
        registered: "2026-10-01T00:00:00Z",
        expires: "2027-10-01T00:00:00Z",
        updated: null,
        registrar: null,
      },
      now,
    );
    expect(young.map((w) => w.id)).toEqual(["new-domain"]);
    const expiring = rdapWarnings(
      {
        domain: "x.com",
        registered: "2010-01-01T00:00:00Z",
        expires: "2026-10-20T00:00:00Z",
        updated: null,
        registrar: null,
      },
      now,
    );
    expect(expiring.map((w) => w.id)).toEqual(["expiring"]);
    expect(rdapWarnings(parseRdap(rdap, "github.com"), now)).toEqual([]);
  });
});

describe("Wayback Machine", () => {
  it("parses the first CDX capture", () => {
    expect(
      parseCdxFirst([
        ["timestamp", "statuscode"],
        ["20080514210148", "200"],
      ]),
    ).toBe("20080514210148");
    expect(parseCdxFirst([["timestamp"]])).toBeNull();
    expect(parseCdxFirst([["timestamp"], ["javascript:alert(1)"]])).toBeNull();
  });

  it("parses sparkline counts and timestamps", () => {
    const s = parseSparkline({
      first_ts: "20080514210148",
      last_ts: "20261010064142",
      years: { "2008": [1, 2, 3], "2009": [10, "x", -5] },
    });
    expect(s).toEqual({ first: "20080514210148", last: "20261010064142", captures: 16 });
    expect(parseSparkline({ years: {}, first_ts: null, last_ts: null, message: "<div>not archived</div>" })).toEqual({
      first: null,
      last: null,
      captures: 0,
    });
  });

  it("builds snapshot links from validated parts", () => {
    expect(timestampToDate("20080514210148").toISOString()).toBe("2008-05-14T21:01:48.000Z");
    expect(snapshotUrl("20080514210148", "github.com")).toBe(
      "https://web.archive.org/web/20080514210148/http://github.com/",
    );
  });
});

describe("IP geolocation", () => {
  const ok = {
    ip: "140.82.114.3",
    success: true,
    country: "United States",
    country_code: "US",
    region: "California",
    city: "San Francisco",
    latitude: 37.77,
    longitude: -122.42,
    connection: { asn: 36459, org: "GitHub, Inc.", isp: "GitHub, Inc." },
  };

  it("parses location and network", () => {
    expect(parseGeo(ok, "140.82.114.3")).toMatchObject({
      city: "San Francisco",
      countryCode: "US",
      asn: 36459,
      latitude: 37.77,
    });
  });

  it("rejects failures and invalid coordinates", () => {
    expect(() => parseGeo({ ...ok, success: false }, "140.82.114.3")).toThrow();
    expect(() => parseGeo(ok, "1.1.1.1")).toThrow();
    const bad = parseGeo({ ...ok, latitude: 999, country_code: "<b>", connection: { asn: -4 } }, "140.82.114.3");
    expect(bad).toMatchObject({ latitude: null, longitude: null, countryCode: null, asn: null });
    expect(parseGeo({ ...ok, latitude: 0, longitude: 0 }, "140.82.114.3").latitude).toBeNull();
  });
});
