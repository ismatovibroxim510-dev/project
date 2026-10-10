import dns from "node:dns";
import http from "node:http";
import https from "node:https";
import { isIP, type LookupFunction } from "node:net";
import tls from "node:tls";
import type { X509Certificate } from "node:crypto";
import { assertPublicHostname, DomainError } from "./domain";
import { isPublicIp } from "./ip";
import type { CertSummary, ProbeResult, TlsDetails, TlsVersionLabel } from "./types";

export const REQUEST_TIMEOUT_MS = 5000;
export const MAX_REDIRECTS = 5;
const USER_AGENT = "Mozilla/5.0 (compatible; SiteGradeScanner/1.0; +security-headers-check)";

export class BlockedAddressError extends Error {
  code = "EBLOCKED";
}

export class TimeoutError extends Error {
  code = "ETIMEDOUT";
}

/**
 * DNS lookup used for every outbound socket. It resolves the hostname and
 * refuses to connect if ANY returned address is private/reserved. Because the
 * check runs inside the socket's own lookup, the address we validate is the
 * address we connect to - there is no window for DNS rebinding.
 */
export const safeLookup: LookupFunction = (hostname, options, callback) => {
  dns.lookup(hostname, { all: true, verbatim: true }, (err, addresses) => {
    if (err) return callback(err, "", 0);
    if (!addresses.length) return callback(new Error(`No addresses for ${hostname}`), "", 0);
    const blocked = addresses.find((a) => !isPublicIp(a.address));
    if (blocked) {
      return callback(new BlockedAddressError(`${hostname} resolves to a non-public address`), "", 0);
    }
    let list = addresses;
    if (options.family === 4 || options.family === 6) {
      list = addresses.filter((a) => a.family === options.family);
      if (!list.length) return callback(new Error(`No IPv${options.family} address for ${hostname}`), "", 0);
    }
    if (options.all) {
      (callback as unknown as (e: null, a: dns.LookupAddress[]) => void)(null, list);
    } else {
      callback(null, list[0].address, list[0].family);
    }
  });
};

/** Resolve a hostname and verify all of its addresses are public. Returns every address (IPv4 first). */
export async function resolvePublicAll(hostname: string): Promise<string[]> {
  const lookup = dns.promises.lookup(hostname, { all: true, verbatim: true });
  const addresses = await withTimeout(lookup, REQUEST_TIMEOUT_MS, "DNS lookup timed out");
  if (!addresses.length) throw new Error("Domain does not resolve");
  if (addresses.some((a) => !isPublicIp(a.address))) {
    throw new BlockedAddressError(`${hostname} resolves to a non-public address`);
  }
  return [...new Set(addresses.map((a) => a.address))].sort((a, b) => Number(isIP(a) === 6) - Number(isIP(b) === 6));
}

/** Resolve a hostname and verify all of its addresses are public. Returns the first address. */
export async function resolvePublic(hostname: string): Promise<string> {
  return (await resolvePublicAll(hostname))[0];
}

export function withTimeout<T>(promise: Promise<T>, ms: number, message: string): Promise<T> {
  let timer: NodeJS.Timeout;
  return Promise.race([
    promise,
    new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new TimeoutError(message)), ms);
    }),
  ]).finally(() => clearTimeout(timer));
}

export interface Hop {
  url: string;
  status: number;
  /** Header values as arrays (duplicates preserved), keys lower-cased. */
  headers: Record<string, string[]>;
  /** TLS certificate validation error (https hops only); null when trusted. */
  tlsError: string | null;
  /** Response body, only when requested with `maxBodyBytes` and the response wasn't a redirect. */
  body?: string;
  /** True when the body exceeded `maxBodyBytes` and was not read. */
  bodyTooLarge?: boolean;
}

export interface FetchOptions {
  /** Read the final (non-redirect) response body, up to this many bytes. Bodies are never read otherwise. */
  maxBodyBytes?: number;
  /** Extra/overriding request headers (e.g. Accept, User-Agent for third-party APIs). */
  headers?: Record<string, string>;
  /**
   * Require a valid certificate. Off for scanned sites (cert problems are reported, not fatal);
   * on for third-party data sources, whose data we only trust over a verified connection.
   */
  verifyTls?: boolean;
}

export interface ChainResult {
  hops: Hop[];
  /** Set when the chain ended in an error instead of a final response. */
  error: string | null;
  errorCode: string | null;
  /** Set when a redirect was intentionally not followed. */
  stoppedReason: string | null;
}

/** Validate a URL before connecting: scheme, port and hostname/IP literal. */
function checkTarget(url: URL): void {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new BlockedAddressError(`Refusing to follow redirect to ${url.protocol} URL`);
  }
  if (url.username || url.password) {
    throw new BlockedAddressError("Refusing to follow redirect containing credentials");
  }
  // Only default ports: stops the scanner being used as a port prober.
  if (url.port !== "") {
    throw new BlockedAddressError(`Not following redirect to non-standard port ${url.port}`);
  }
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (isIP(host)) {
    // IP literals bypass the lookup function, so check them explicitly.
    if (!isPublicIp(host)) throw new BlockedAddressError("Redirect points to a non-public IP address");
    return;
  }
  try {
    assertPublicHostname(host);
  } catch (e) {
    if (e instanceof DomainError) throw new BlockedAddressError(`Redirect to disallowed host ${host}`);
    throw e;
  }
}

/**
 * Single GET request. Resolves as soon as the response headers arrive, unless
 * `maxBodyBytes` is set and the response isn't a redirect - then the body is read
 * up to that limit (the 5s timeout covers the body too).
 */
function requestOnce(url: URL, opts: FetchOptions = {}): Promise<Hop> {
  return new Promise((resolve, reject) => {
    const isHttps = url.protocol === "https:";
    const options: https.RequestOptions = {
      method: "GET",
      headers: {
        "User-Agent": USER_AGENT,
        Accept: "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8",
        "Accept-Encoding": "identity",
        "Accept-Language": "en",
        ...opts.headers,
      },
      lookup: safeLookup,
      agent: false,
      maxHeaderSize: 64 * 1024,
      // Certificate problems are reported by the TLS check; we still want headers.
      ...(isHttps ? { rejectUnauthorized: !!opts.verifyTls, minVersion: "TLSv1.2" as const } : {}),
    };

    const req = (isHttps ? https : http).request(url, options, (res) => {
      const socket = res.socket as tls.TLSSocket;
      const tlsError = isHttps && !socket.authorized ? String(socket.authorizationError ?? "UNTRUSTED") : null;
      const headers: Record<string, string[]> = {};
      for (const [k, v] of Object.entries(res.headersDistinct)) {
        if (v) headers[k.toLowerCase()] = v;
      }
      const hop: Hop = { url: url.toString(), status: res.statusCode ?? 0, headers, tlsError };
      const status = res.statusCode ?? 0;
      const limit = opts.maxBodyBytes;
      if (!limit || (status >= 300 && status < 400)) {
        clearTimeout(timer);
        resolve(hop);
        res.destroy();
        return;
      }
      const declared = Number(res.headers["content-length"]);
      if (Number.isFinite(declared) && declared > limit) {
        clearTimeout(timer);
        resolve({ ...hop, bodyTooLarge: true });
        res.destroy();
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (chunk: Buffer) => {
        size += chunk.length;
        if (size > limit) {
          clearTimeout(timer);
          resolve({ ...hop, bodyTooLarge: true });
          res.destroy();
          return;
        }
        chunks.push(chunk);
      });
      res.on("end", () => {
        clearTimeout(timer);
        resolve({ ...hop, body: Buffer.concat(chunks).toString("utf8") });
      });
      res.on("error", (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });

    const timer = setTimeout(() => {
      req.destroy(new TimeoutError(`Request to ${url.host} timed out after ${REQUEST_TIMEOUT_MS / 1000}s`));
    }, REQUEST_TIMEOUT_MS);

    req.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
    req.end();
  });
}

/** GET a URL, manually following up to MAX_REDIRECTS redirects, re-validating every hop. */
export async function fetchChain(startUrl: string, opts: FetchOptions = {}): Promise<ChainResult> {
  const hops: Hop[] = [];
  let url = new URL(startUrl);
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    try {
      checkTarget(url);
    } catch (e) {
      return { hops, error: null, errorCode: null, stoppedReason: (e as Error).message };
    }
    let hop: Hop;
    try {
      hop = await requestOnce(url, opts);
    } catch (e) {
      const err = e as NodeJS.ErrnoException;
      return { hops, error: friendlyNetError(err), errorCode: err.code ?? null, stoppedReason: null };
    }
    hops.push(hop);

    const location = hop.headers["location"]?.[0];
    if (hop.status >= 300 && hop.status < 400 && location) {
      if (i === MAX_REDIRECTS) {
        return { hops, error: null, errorCode: null, stoppedReason: `Stopped after ${MAX_REDIRECTS} redirects` };
      }
      try {
        url = new URL(location, url);
      } catch {
        return { hops, error: null, errorCode: null, stoppedReason: "Invalid redirect Location header" };
      }
      continue;
    }
    return { hops, error: null, errorCode: null, stoppedReason: null };
  }
  return { hops, error: null, errorCode: null, stoppedReason: `Stopped after ${MAX_REDIRECTS} redirects` };
}

export function friendlyNetError(err: NodeJS.ErrnoException): string {
  switch (err.code) {
    case "EBLOCKED":
      return err.message;
    case "ETIMEDOUT":
      return err.message || "Connection timed out";
    case "ECONNREFUSED":
      return "Connection refused";
    case "ECONNRESET":
      return "Connection was reset by the server";
    case "ENOTFOUND":
    case "EAI_AGAIN":
      return "Domain could not be resolved";
    case "EHOSTUNREACH":
    case "ENETUNREACH":
      return "Host is unreachable";
    case "EPROTO":
    case "ERR_SSL_WRONG_VERSION_NUMBER":
    case "ERR_SSL_UNSUPPORTED_PROTOCOL":
    case "ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION":
      return "TLS handshake failed (the server may not support HTTPS, or only outdated TLS versions)";
    case "HPE_HEADER_OVERFLOW":
      return "Response headers were too large";
    default:
      return err.message ? err.message.slice(0, 200) : "Network error";
  }
}

export interface TlsInfo {
  authorized: boolean;
  authorizationError: string | null;
  protocol: string | null;
  cipher: string | null;
  keyExchange: string | null;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  /** Every DNS name on the certificate (not capped). */
  altNames: string[];
  key: { type: string; bits: number | null } | null;
  signatureAlgorithm: string | null;
  chain: CertSummary[];
}

const CURVE_BITS: Record<string, number> = {
  prime256v1: 256,
  secp256r1: 256,
  secp256k1: 256,
  secp384r1: 384,
  secp521r1: 521,
  secp224r1: 224,
  prime192v1: 192,
};

/** "C=GB\nO=Sectigo Limited\nCN=Sectigo CA" -> { C: "GB", O: "...", CN: "..." } */
export function parseDn(dn: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of (dn ?? "").split("\n")) {
    const eq = line.indexOf("=");
    if (eq > 0 && !(line.slice(0, eq) in out)) out[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return out;
}

export function describeKey(cert: X509Certificate): { type: string; bits: number | null } {
  const key = cert.publicKey;
  const type = key.asymmetricKeyType ?? "unknown";
  const d = key.asymmetricKeyDetails ?? {};
  if (d.modulusLength) return { type: type.toUpperCase(), bits: d.modulusLength };
  if (type === "ec") return { type: "EC", bits: d.namedCurve ? (CURVE_BITS[d.namedCurve] ?? null) : null };
  if (type === "ed25519") return { type: "Ed25519", bits: 256 };
  if (type === "ed448") return { type: "Ed448", bits: 456 };
  return { type, bits: null };
}

function summarizeChain(leaf: X509Certificate): CertSummary[] {
  const chain: CertSummary[] = [];
  let cert: X509Certificate | undefined = leaf;
  // The chain as presented by the server (plus anything Node could link up), capped for safety.
  while (cert && chain.length < 6) {
    const subject = parseDn(cert.subject);
    const issuer = parseDn(cert.issuer);
    const selfSigned = cert.subject === cert.issuer;
    const key = describeKey(cert);
    chain.push({
      subject: subject.CN ?? subject.O ?? cert.subject.replace(/\n/g, ", "),
      issuer: issuer.CN ?? issuer.O ?? cert.issuer.replace(/\n/g, ", "),
      validTo: cert.validTo,
      key: `${key.type}${key.bits ? ` ${key.bits}-bit` : ""}`,
      signatureAlgorithm: cert.signatureAlgorithm ?? "unknown",
      role: chain.length === 0 ? "leaf" : selfSigned ? "root" : "intermediate",
    });
    const next: X509Certificate | undefined = cert.issuerCertificate;
    if (!next || selfSigned || next.fingerprint256 === cert.fingerprint256) break;
    cert = next;
  }
  return chain;
}

/** Open a TLS connection to host:443 (TLS 1.2+, normal settings) and read the certificate and connection details. */
export function inspectTls(host: string): Promise<TlsInfo> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host,
      port: 443,
      servername: host,
      lookup: safeLookup,
      rejectUnauthorized: false,
      minVersion: "TLSv1.2",
      ALPNProtocols: ["http/1.1"],
    });
    const timer = setTimeout(() => {
      socket.destroy(new TimeoutError(`TLS connection timed out after ${REQUEST_TIMEOUT_MS / 1000}s`));
    }, REQUEST_TIMEOUT_MS);

    socket.once("secureConnect", () => {
      clearTimeout(timer);
      const cert = socket.getPeerX509Certificate();
      const cipher = socket.getCipher();
      const eph = socket.getEphemeralKeyInfo();
      const keyExchange =
        eph && "name" in eph && eph.name ? `${eph.name}${eph.size ? ` (${eph.size}-bit)` : ""}` : null;
      const subject = parseDn(cert?.subject);
      const issuer = parseDn(cert?.issuer);
      resolve({
        authorized: socket.authorized,
        authorizationError: socket.authorized ? null : String(socket.authorizationError ?? "UNKNOWN"),
        protocol: socket.getProtocol(),
        cipher: cipher?.standardName ?? cipher?.name ?? null,
        keyExchange,
        issuer: cert ? issuer.O || issuer.CN || null : null,
        subject: cert ? subject.CN || subject.O || null : null,
        validFrom: cert?.validFrom ?? null,
        validTo: cert?.validTo ?? null,
        altNames: (cert?.subjectAltName ?? "")
          .split(", ")
          .filter((s) => s.startsWith("DNS:"))
          .map((s) => s.slice(4)),
        key: cert ? describeKey(cert) : null,
        signatureAlgorithm: cert?.signatureAlgorithm ?? null,
        chain: cert ? summarizeChain(cert) : [],
      });
      socket.end();
    });
    socket.once("error", (err) => {
      clearTimeout(timer);
      socket.destroy();
      reject(err);
    });
  });
}

/** Errors that mean "the server refused this protocol version" rather than "we couldn't reach it". */
const REJECTION_CODES = /^(ERR_SSL_|EPROTO$|ECONNRESET$)/;

export interface ProbeOptions {
  /** Tests only: connect to a different port / bypass DNS. Production code never passes these. */
  port?: number;
  lookup?: LookupFunction;
}

/**
 * One TLS handshake pinned to exactly `version`, used only to learn whether the
 * server still accepts it. TLS 1.0/1.1 are disabled by OpenSSL's default security
 * level, so ONLY for those probes we lower it with @SECLEVEL=0. These settings are
 * confined to this function; nothing is sent over the connection.
 */
export function probeTlsVersion(
  host: string,
  version: tls.SecureVersion,
  opts: ProbeOptions = {},
): Promise<ProbeResult> {
  const legacy = version === "TLSv1" || version === "TLSv1.1";
  return new Promise((resolve) => {
    const socket = tls.connect({
      host,
      port: opts.port ?? 443,
      servername: host,
      lookup: opts.lookup ?? safeLookup,
      rejectUnauthorized: false,
      minVersion: version,
      maxVersion: version,
      ...(legacy ? { ciphers: "DEFAULT:@SECLEVEL=0" } : {}),
    });
    const timer = setTimeout(() => {
      socket.destroy();
      resolve("unknown");
    }, REQUEST_TIMEOUT_MS);
    socket.once("secureConnect", () => {
      clearTimeout(timer);
      resolve(socket.getProtocol() === version ? "supported" : "rejected");
      socket.destroy();
    });
    socket.once("error", (err: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      socket.destroy();
      resolve(err.code && REJECTION_CODES.test(err.code) ? "rejected" : "unknown");
    });
  });
}

export const PROBED_VERSIONS: Array<{ version: tls.SecureVersion; label: TlsVersionLabel }> = [
  { version: "TLSv1", label: "TLS 1.0" },
  { version: "TLSv1.1", label: "TLS 1.1" },
  { version: "TLSv1.2", label: "TLS 1.2" },
  { version: "TLSv1.3", label: "TLS 1.3" },
];

export async function probeTlsVersions(host: string, opts: ProbeOptions = {}): Promise<TlsDetails["protocols"]> {
  return Promise.all(
    PROBED_VERSIONS.map(async ({ version, label }) => ({
      version: label,
      result: await probeTlsVersion(host, version, opts),
    })),
  );
}
