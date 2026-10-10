import { describe, expect, it } from "vitest";
import { GET } from "@/app/frame-demo/route";
import { parseFrameTarget } from "@/lib/frame-demo";

const req = (url: string | null, dest: string | null = "iframe") =>
  new Request(`https://sitegrade.test/frame-demo${url === null ? "" : `?url=${encodeURIComponent(url)}`}`, {
    headers: dest ? { "sec-fetch-dest": dest } : {},
  });

describe("clickjacking demo target", () => {
  it.each(["https://example.com/", "https://www.example.com/en-US/?q=1"])("accepts %s", (u) => {
    expect(parseFrameTarget(u)).not.toBeNull();
  });

  it.each([
    null,
    "",
    "http://example.com/",
    "https://127.0.0.1/",
    "https://[::1]/",
    "https://localhost/",
    "https://router.local/",
    "https://example.com:8443/",
    "https://user:pw@example.com/",
    "javascript:alert(1)",
    "data:text/html,<script>alert(1)</script>",
    "https://exa mple.com/",
    `https://${"a".repeat(2100)}.com/`,
  ])("rejects %j", (u) => {
    expect(parseFrameTarget(u)).toBeNull();
  });
});

describe("/frame-demo route", () => {
  it("allows framing exactly the scanned origin, sandboxed, and only by our own pages", async () => {
    const res = GET(req("https://www.example.com/en-US/"));
    expect(res.status).toBe(200);
    const csp = res.headers.get("content-security-policy")!;
    expect(csp).toContain("frame-src https://www.example.com;");
    expect(csp).toContain("frame-ancestors 'self'");
    expect(csp).toContain("default-src 'none'");
    expect(csp).not.toMatch(/script-src|\*/);
    expect(res.headers.get("x-frame-options")).toBe("SAMEORIGIN");
    const html = await res.text();
    expect(html).toContain('<iframe src="https://www.example.com/en-US/" sandbox=""');
  });

  it("escapes the URL in the HTML", async () => {
    const html = await GET(req('https://example.com/?a="><script>alert(1)</script>')).text();
    expect(html).not.toContain("<script>");
  });

  it("rejects invalid targets", () => {
    expect(GET(req("http://example.com/")).status).toBe(400);
    expect(GET(req("https://10.0.0.1/")).status).toBe(400);
    expect(GET(req(null)).status).toBe(400);
  });

  it("does not embed anything when opened directly as a page", async () => {
    const res = GET(req("https://example.com/", "document"));
    expect(res.status).toBe(400);
    expect(await res.text()).not.toContain("<iframe");
  });
});
