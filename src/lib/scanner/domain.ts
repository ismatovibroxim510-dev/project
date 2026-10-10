import { isIP } from "node:net";
import { domainToASCII } from "node:url";

/** TLDs / suffixes that never point at the public internet. */
const RESERVED_SUFFIXES = [
  "localhost",
  "local",
  "localdomain",
  "internal",
  "intranet",
  "private",
  "corp",
  "home",
  "lan",
  "test",
  "example",
  "invalid",
  "onion",
  "arpa",
  "alt",
];

const LABEL_RE = /^(?!-)[a-z0-9-]{1,63}(?<!-)$/;
const TLD_RE = /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/;

export class DomainError extends Error {}

/**
 * Normalises user input ("https://Example.com/path?x" -> "example.com") and
 * rejects anything that is not a syntactically valid public hostname.
 * Throws DomainError with a user-facing message.
 */
export function normalizeDomain(input: unknown): string {
  if (typeof input !== "string") throw new DomainError("Enter a domain name, e.g. example.com.");
  const raw = input.trim();
  if (!raw) throw new DomainError("Enter a domain name, e.g. example.com.");
  if (raw.length > 2048) throw new DomainError("That input is too long.");
  // Reject whitespace and control characters anywhere in the input.
  if (/[\s\u0000-\u001f\u007f]/.test(raw)) throw new DomainError("Domain names cannot contain spaces.");

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `http://${raw}`;
  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new DomainError("That doesn't look like a valid domain.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new DomainError("Only http and https sites can be scanned.");
  }

  let host = url.hostname.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);
  return assertPublicHostname(host);
}

/** Validates an already-parsed hostname (also used for redirect targets). */
export function assertPublicHostname(hostname: string): string {
  let host = hostname.toLowerCase();
  if (host.endsWith(".")) host = host.slice(0, -1);

  if (host.startsWith("[") || isIP(host)) {
    throw new DomainError("Enter a domain name, not an IP address.");
  }

  const ascii = domainToASCII(host);
  if (!ascii) throw new DomainError("That doesn't look like a valid domain.");
  if (ascii.length > 253) throw new DomainError("That domain name is too long.");

  const labels = ascii.split(".");
  if (labels.length < 2) throw new DomainError("Enter a full domain including its extension, e.g. example.com.");
  if (!labels.every((l) => LABEL_RE.test(l))) throw new DomainError("That doesn't look like a valid domain.");

  const tld = labels[labels.length - 1];
  if (!TLD_RE.test(tld)) throw new DomainError("That doesn't look like a valid domain.");
  if (RESERVED_SUFFIXES.includes(tld) || ascii.endsWith(".home.arpa")) {
    throw new DomainError("Internal and reserved domains can't be scanned.");
  }
  return ascii;
}
