import type { CategoryId, Grade } from "./types";

/**
 * Points per check, for documentation (About page, README). A unit test checks
 * these against what the checks actually award, so the docs can't drift.
 */
export const CHECK_WEIGHTS: Record<CategoryId, Array<{ id: string; label: string; points: number }>> = {
  https: [
    { id: "https-available", label: "Site loads over HTTPS", points: 8 },
    { id: "http-redirect", label: "HTTP redirects to HTTPS", points: 4 },
  ],
  tls: [
    { id: "tls-valid", label: "Certificate trusted and matches the domain", points: 10 },
    { id: "tls-expiry", label: "Certificate not expiring within 30 days", points: 4 },
    { id: "tls-protocols", label: "TLS 1.0/1.1 refused, TLS 1.2/1.3 supported", points: 5 },
    { id: "tls-key", label: "Key strength (RSA ≥ 2048, EC ≥ 224)", points: 2 },
    { id: "tls-signature", label: "No SHA-1/MD5 signatures", points: 1 },
  ],
  headers: [
    { id: "hsts", label: "Strict-Transport-Security", points: 7 },
    { id: "csp", label: "Content-Security-Policy", points: 9 },
    { id: "x-frame-options", label: "X-Frame-Options / frame-ancestors", points: 5 },
    { id: "x-content-type-options", label: "X-Content-Type-Options", points: 5 },
    { id: "referrer-policy", label: "Referrer-Policy", points: 3 },
    { id: "permissions-policy", label: "Permissions-Policy", points: 3 },
  ],
  cookies: [
    { id: "cookie-secure", label: "Secure flag", points: 4 },
    { id: "cookie-httponly", label: "HttpOnly flag", points: 2 },
    { id: "cookie-samesite", label: "SameSite attribute", points: 2 },
  ],
  leakage: [
    { id: "server-header", label: "No version in Server header", points: 3 },
    { id: "powered-by", label: "No X-Powered-By and similar headers", points: 2 },
    { id: "technologies", label: "Detected technologies (informational)", points: 0 },
  ],
  email: [
    { id: "spf", label: "SPF record ending in -all or ~all", points: 5 },
    { id: "dmarc", label: "DMARC policy quarantine or reject", points: 7 },
  ],
  dns: [
    { id: "caa", label: "CAA record", points: 3 },
    { id: "dnssec", label: "DNSSEC", points: 3 },
  ],
  files: [
    { id: "security-txt", label: "Valid security.txt", points: 3 },
    { id: "robots-txt", label: "robots.txt review (informational)", points: 0 },
  ],
};

export const GRADE_CAPS: Array<{ grade: Grade; when: string }> = [
  { grade: "F", when: "the site can't be loaded over HTTPS" },
  { grade: "D", when: "the certificate is untrusted or expired" },
  { grade: "C", when: "the certificate uses a weak key" },
  { grade: "C", when: "Shodan's public data shows a database reachable from the internet" },
  { grade: "B", when: "the server still accepts TLS 1.0 or 1.1" },
];
