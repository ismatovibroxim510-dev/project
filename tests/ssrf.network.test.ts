/**
 * Live network tests for SSRF protection. Skipped unless NETWORK_TESTS=1.
 *   NETWORK_TESTS=1 npm test
 */
import { describe, expect, it } from "vitest";
import { fetchChain, resolvePublic } from "@/lib/scanner/net";

describe.skipIf(!process.env.NETWORK_TESTS)("SSRF protection (network)", () => {
  it("refuses domains that resolve to loopback", async () => {
    await expect(resolvePublic("localtest.me")).rejects.toThrow(/non-public/);
  });

  it("does not follow a redirect to a private IP", async () => {
    const chain = await fetchChain("https://httpbin.org/redirect-to?url=http%3A%2F%2F127.0.0.1%2F");
    expect(chain.hops).toHaveLength(1);
    expect(chain.hops[0].status).toBeGreaterThanOrEqual(300);
    expect(chain.stoppedReason).toMatch(/non-public/);
  });

  it("does not follow a redirect to cloud metadata", async () => {
    const chain = await fetchChain(
      "https://httpbin.org/redirect-to?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F",
    );
    expect(chain.hops).toHaveLength(1);
    expect(chain.stoppedReason).toMatch(/non-public/);
  });

  it("does not follow a redirect to a hostname resolving to loopback", async () => {
    const chain = await fetchChain("https://httpbin.org/redirect-to?url=http%3A%2F%2Flocaltest.me%2F");
    expect(chain.hops).toHaveLength(1);
    expect(chain.errorCode).toBe("EBLOCKED");
  });

  it("does not follow redirects to non-standard ports", async () => {
    const chain = await fetchChain("https://httpbin.org/redirect-to?url=http%3A%2F%2Fexample.com%3A6379%2F");
    expect(chain.stoppedReason).toMatch(/port/);
  });

  it("stops after 5 redirects", async () => {
    const chain = await fetchChain("https://httpbin.org/redirect/8");
    expect(chain.hops).toHaveLength(6);
    expect(chain.stoppedReason).toMatch(/5 redirects/);
  });
});

describe.skipIf(!process.env.NETWORK_TESTS)("bounded body reads (network)", () => {
  it("refuses bodies larger than the limit", async () => {
    const chain = await fetchChain("https://github.com/robots.txt", { maxBodyBytes: 100 });
    expect(chain.hops.at(-1)?.bodyTooLarge).toBe(true);
    expect(chain.hops.at(-1)?.body).toBeUndefined();
  });
  it("reads bodies within the limit", async () => {
    const chain = await fetchChain("https://github.com/robots.txt", { maxBodyBytes: 64 * 1024 });
    expect(chain.hops.at(-1)?.body).toMatch(/Disallow/);
  });
});

describe.skipIf(!process.env.NETWORK_TESTS)("TLS probes (network)", () => {
  it("detects TLS 1.0 on tls-v1-0.badssl.com and not on github.com", async () => {
    const { probeTlsVersion } = await import("@/lib/scanner/net");
    expect(await probeTlsVersion("tls-v1-0.badssl.com", "TLSv1", { port: 1010 })).toBe("supported");
    expect(await probeTlsVersion("github.com", "TLSv1")).toBe("rejected");
    expect(await probeTlsVersion("github.com", "TLSv1.3")).toBe("supported");
  });
});
