import { describe, expect, it } from "vitest";
import { DomainError, normalizeDomain } from "@/lib/scanner/domain";

describe("normalizeDomain", () => {
  it.each([
    ["example.com", "example.com"],
    ["  Example.COM  ", "example.com"],
    ["https://example.com/path?q=1#x", "example.com"],
    ["http://user:pass@example.com:8080/a", "example.com"],
    ["www.example.co.uk.", "www.example.co.uk"],
    ["bücher.de", "xn--bcher-kva.de"],
    ["sub-domain.example.io", "sub-domain.example.io"],
  ])("accepts %s", (input, expected) => {
    expect(normalizeDomain(input)).toBe(expected);
  });

  it.each([
    "",
    "   ",
    "localhost",
    "foo",
    "127.0.0.1",
    "0x7f.1",
    "2130706433",
    "[::1]",
    "http://[fe80::1]/",
    "169.254.169.254",
    "metadata.google.internal",
    "printer.local",
    "router.lan",
    "site.test",
    "x.onion",
    "1.0.0.10.in-addr.arpa",
    "ftp://example.com",
    "javascript:alert(1)",
    "exa mple.com",
    "-bad.com",
    "bad-.com",
    "<script>alert(1)</script>.com",
    "example.123",
    `${"a".repeat(64)}.com`,
    "a".repeat(3000),
  ])("rejects %j", (input) => {
    expect(() => normalizeDomain(input)).toThrow(DomainError);
  });

  it("rejects non-strings", () => {
    expect(() => normalizeDomain(42)).toThrow(DomainError);
    expect(() => normalizeDomain(null)).toThrow(DomainError);
    expect(() => normalizeDomain({})).toThrow(DomainError);
  });
});
