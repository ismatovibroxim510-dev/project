import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import type { LookupFunction } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import tls from "node:tls";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { checkTls, isWeakKey, isWeakSignature } from "@/lib/scanner/checks/tls";
import { probeTlsVersion, type TlsInfo } from "@/lib/scanner/net";
import { computeGrade } from "@/lib/scanner/scoring";
import type { TlsDetails } from "@/lib/scanner/types";

const MODERN: TlsDetails["protocols"] = [
  { version: "TLS 1.0", result: "rejected" },
  { version: "TLS 1.1", result: "rejected" },
  { version: "TLS 1.2", result: "supported" },
  { version: "TLS 1.3", result: "supported" },
];

function info(overrides: Partial<TlsInfo> = {}): TlsInfo {
  return {
    authorized: true,
    authorizationError: null,
    protocol: "TLSv1.3",
    cipher: "TLS_AES_128_GCM_SHA256",
    keyExchange: "X25519",
    issuer: "Let's Encrypt",
    subject: "example.com",
    validFrom: "Jan 1 00:00:00 2026 GMT",
    validTo: new Date(Date.now() + 80 * 86400e3).toUTCString(),
    altNames: ["example.com", "www.example.com"],
    key: { type: "EC", bits: 256 },
    signatureAlgorithm: "ecdsa-with-SHA256",
    chain: [
      {
        subject: "example.com",
        issuer: "E6",
        validTo: "",
        key: "EC 256-bit",
        signatureAlgorithm: "ecdsa-with-SHA384",
        role: "leaf",
      },
    ],
    ...overrides,
  };
}

const find = (r: ReturnType<typeof checkTls>, id: string) => r.category.findings.find((f) => f.id === id)!;

describe("TLS analysis", () => {
  it("gives full marks to a modern configuration", () => {
    const r = checkTls("example.com", { info: info() }, MODERN);
    expect(r.category.score).toBe(22);
    expect(r.details.protocols).toEqual(MODERN);
  });

  it("fails and caps the grade at B when TLS 1.0 is accepted", () => {
    const legacy = MODERN.map((p) => (p.version === "TLS 1.0" ? { ...p, result: "supported" as const } : p));
    const r = checkTls("example.com", { info: info() }, legacy);
    expect(find(r, "tls-protocols").status).toBe("fail");
    const other = { ...r.category, id: "headers" as const, score: 78, findings: [] };
    expect(computeGrade([r.category, other]).grade).toBe("B");
    expect(computeGrade([r.category, other]).cap?.reason).toMatch(/TLS 1\.0\/1\.1/);
  });

  it("warns when only TLS 1.1 is accepted", () => {
    const r = checkTls(
      "example.com",
      { info: info() },
      MODERN.map((p) => (p.version === "TLS 1.1" ? { ...p, result: "supported" as const } : p)),
    );
    expect(find(r, "tls-protocols").status).toBe("warn");
  });

  it("does not apply the legacy cap when support simply couldn't be confirmed", () => {
    const unknown = MODERN.map((p) => ({ ...p, result: "unknown" as const }));
    const r = checkTls("example.com", { info: info() }, unknown);
    expect(find(r, "tls-protocols").status).toBe("warn");
    const other = { ...r.category, id: "headers" as const, score: 78, findings: [] };
    expect(computeGrade([r.category, other]).cap).toBeNull();
  });

  it("detects weak keys and signatures", () => {
    expect(isWeakKey({ type: "RSA", bits: 1024 })).toBe(true);
    expect(isWeakKey({ type: "RSA", bits: 2048 })).toBe(false);
    expect(isWeakKey({ type: "EC", bits: 192 })).toBe(true);
    expect(isWeakKey({ type: "EC", bits: 256 })).toBe(false);
    expect(isWeakKey({ type: "Ed25519", bits: 256 })).toBe(false);
    expect(isWeakSignature("sha1WithRSAEncryption")).toBe(true);
    expect(isWeakSignature("ecdsa-with-SHA1")).toBe(true);
    expect(isWeakSignature("md5WithRSAEncryption")).toBe(true);
    expect(isWeakSignature("sha256WithRSAEncryption")).toBe(false);
    expect(isWeakSignature("ecdsa-with-SHA384")).toBe(false);
  });

  it("penalises a weak key and caps the grade at C", () => {
    const r = checkTls("example.com", { info: info({ key: { type: "RSA", bits: 1024 } }) }, MODERN);
    expect(find(r, "tls-key").status).toBe("fail");
    const other = { ...r.category, id: "headers" as const, score: 78, findings: [] };
    expect(computeGrade([r.category, other]).grade).toBe("C");
  });

  it("flags a SHA-1 signature in the chain", () => {
    const r = checkTls(
      "example.com",
      {
        info: info({
          chain: [
            {
              subject: "example.com",
              issuer: "Old CA",
              validTo: "",
              key: "RSA 2048-bit",
              signatureAlgorithm: "sha1WithRSAEncryption",
              role: "leaf",
            },
          ],
        }),
      },
      MODERN,
    );
    expect(find(r, "tls-signature").status).toBe("fail");
  });

  it("caps the SAN list for display and reports other domains", () => {
    const names = Array.from({ length: 40 }, (_, i) => `site${i}.example${i % 3}.com`);
    const r = checkTls("example0.com", { info: info({ altNames: names }) }, MODERN);
    expect(r.details.sans).toHaveLength(25);
    expect(r.details.sanTotal).toBe(40);
    expect(find(r, "tls-details").summary).toMatch(/2 other domains/);
    expect(find(r, "tls-details").maxPoints).toBe(0);
  });

  it("handles a failed connection", () => {
    const err = Object.assign(new Error("refused"), { code: "ECONNREFUSED" });
    const r = checkTls("example.com", { error: err }, MODERN);
    expect(find(r, "tls-valid").status).toBe("fail");
    expect(r.category.maxScore).toBe(22);
  });
});

// A local TLS server lets us test real pinned-version handshakes without the network.
// The probe normally refuses loopback addresses (SSRF guard), so these tests inject a lookup.
describe("TLS version probe (local server)", () => {
  let dir: string;
  let legacyServer: tls.Server;
  let modernServer: tls.Server;
  let legacyPort = 0;
  let modernPort = 0;
  let connections = 0;
  const toLoopback: LookupFunction = (_host, opts, cb) => {
    if (opts.all)
      (cb as unknown as (e: null, a: { address: string; family: number }[]) => void)(null, [
        { address: "127.0.0.1", family: 4 },
      ]);
    else cb(null, "127.0.0.1", 4);
  };

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), "sitegrade-tls-"));
    execFileSync(
      "openssl",
      [
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-subj",
        "/CN=test.local",
        "-keyout",
        join(dir, "key.pem"),
        "-out",
        join(dir, "cert.pem"),
      ],
      { stdio: "ignore" },
    );
    const key = readFileSync(join(dir, "key.pem"));
    const cert = readFileSync(join(dir, "cert.pem"));
    const listen = (server: tls.Server) =>
      new Promise<number>((r) => server.listen(0, "127.0.0.1", () => r((server.address() as { port: number }).port)));
    legacyServer = tls.createServer({
      key,
      cert,
      minVersion: "TLSv1",
      maxVersion: "TLSv1.1",
      ciphers: "DEFAULT:@SECLEVEL=0",
    });
    modernServer = tls.createServer({ key, cert, minVersion: "TLSv1.2" });
    modernServer.on("connection", () => connections++);
    legacyServer.on("connection", () => connections++);
    legacyPort = await listen(legacyServer);
    modernPort = await listen(modernServer);
  });

  afterAll(() => {
    legacyServer?.close();
    modernServer?.close();
  });

  it("detects a server that only speaks TLS 1.0/1.1", async () => {
    const opts = { port: legacyPort, lookup: toLoopback };
    expect(await probeTlsVersion("test.local", "TLSv1", opts)).toBe("supported");
    expect(await probeTlsVersion("test.local", "TLSv1.1", opts)).toBe("supported");
    expect(await probeTlsVersion("test.local", "TLSv1.2", opts)).toBe("rejected");
    expect(await probeTlsVersion("test.local", "TLSv1.3", opts)).toBe("rejected");
  });

  it("detects a modern server that refuses TLS 1.0/1.1", async () => {
    const opts = { port: modernPort, lookup: toLoopback };
    expect(await probeTlsVersion("test.local", "TLSv1", opts)).toBe("rejected");
    expect(await probeTlsVersion("test.local", "TLSv1.1", opts)).toBe("rejected");
    expect(await probeTlsVersion("test.local", "TLSv1.2", opts)).toBe("supported");
    expect(await probeTlsVersion("test.local", "TLSv1.3", opts)).toBe("supported");
  });

  it("keeps the SSRF guard: with the default lookup, loopback is never contacted", async () => {
    const before = connections;
    expect(await probeTlsVersion("localhost", "TLSv1.2", { port: modernPort })).toBe("unknown");
    expect(connections).toBe(before);
  });
});
