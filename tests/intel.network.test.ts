/**
 * Live tests against the real public data sources. Skipped unless NETWORK_TESTS=1.
 */
import { describe, expect, it } from "vitest";
import { clearIntelCache } from "@/lib/intel/cache";
import { getGeo } from "@/lib/intel/geo";
import { getBreaches } from "@/lib/intel/hibp";
import { getRdap } from "@/lib/intel/rdap";
import { getShodan } from "@/lib/intel/shodan";
import { getWayback } from "@/lib/intel/wayback";
import { resolvePublicAll } from "@/lib/scanner/net";

describe.skipIf(!process.env.NETWORK_TESTS)("public data sources (network)", () => {
  it("Shodan InternetDB returns validated port data", async () => {
    clearIntelCache();
    const ips = await resolvePublicAll("github.com");
    const s = await getShodan(ips);
    expect(s).not.toBeNull();
    expect(s!.hosts.length + s!.noData.length).toBeGreaterThan(0);
    for (const h of s!.hosts) expect(h.ports.every((p) => p.port > 0 && p.port < 65536)).toBe(true);
  });

  it("HIBP returns breaches with plain-text descriptions", async () => {
    const b = await getBreaches("adobe.com");
    expect(b?.breaches[0].name).toBe("Adobe");
    expect(b?.breaches[0].description).not.toMatch(/<[a-z]/i);
    expect((await getBreaches("example.com"))?.total).toBe(0);
  });

  it("RDAP follows the registry redirect", async () => {
    const r = await getRdap("github.com");
    expect(r?.registered?.slice(0, 4)).toBe("2007");
    expect(r?.registrar).toBeTruthy();
  });

  it("Wayback Machine reports the first snapshot", async () => {
    const w = await getWayback("github.com");
    expect(w?.firstTimestamp?.slice(0, 4)).toBe("2008");
  });

  it("ipwho.is geolocates a public IP and refuses private ones", async () => {
    expect((await getGeo("8.8.8.8"))?.countryCode).toBe("US");
    expect(await getGeo("10.0.0.1")).toBeNull();
  });
});
