import type { IntelDataMap, IntelSource } from "@/lib/intel/types";

export type Status = "pass" | "warn" | "fail" | "info";

export type CategoryId = "https" | "tls" | "headers" | "cookies" | "leakage" | "email" | "dns" | "files";

export interface Finding {
  id: string;
  title: string;
  status: Status;
  points: number;
  /** 0 for informational findings that don't affect the score. */
  maxPoints: number;
  /** One line describing what we observed. */
  summary: string;
  /** Plain-English explanation of why this matters. */
  explanation: string;
  /** How to fix it. Omitted when there is nothing to fix. */
  fix?: string;
  /** Raw observed value (header value, DNS record...). Always rendered as text, never HTML. */
  evidence?: string;
}

export interface CategoryResult {
  id: CategoryId;
  title: string;
  description: string;
  score: number;
  maxScore: number;
  status: Status;
  findings: Finding[];
}

export type Grade = "A+" | "A" | "B" | "C" | "D" | "F";

export interface GradeCap {
  grade: Grade;
  reason: string;
}

export type TlsVersionLabel = "TLS 1.0" | "TLS 1.1" | "TLS 1.2" | "TLS 1.3";
export type ProbeResult = "supported" | "rejected" | "unknown";

export interface CertSummary {
  subject: string;
  issuer: string;
  validTo: string;
  key: string;
  signatureAlgorithm: string;
  role: "leaf" | "intermediate" | "root";
}

export interface TlsDetails {
  protocols: Array<{ version: TlsVersionLabel; result: ProbeResult }>;
  negotiated: string | null;
  cipher: string | null;
  keyExchange: string | null;
  key: { type: string; bits: number | null } | null;
  signatureAlgorithm: string | null;
  issuerOrg: string | null;
  chain: CertSummary[];
  /** Names on the certificate (capped for display); sanTotal is the real count. */
  sans: string[];
  sanTotal: number;
}

export interface Technology {
  name: string;
  category: string;
  version: string | null;
  /** Where it was detected, e.g. "Server header" or "cookie PHPSESSID". */
  source: string;
}

export interface RobotsDetails {
  found: boolean;
  disallow: string[];
  sensitive: string[];
  total: number;
}

export interface ReportDetails {
  tls: TlsDetails | null;
  technologies: Technology[];
  robots: RobotsDetails;
  email: { domain: string; spfRecord: string | null };
  /** Clickjacking demo: only set when the final page has no framing protection. */
  frame: { frameable: boolean; url: string | null };
}

/** A score deduction outside the eight categories (e.g. services exposed to the internet). */
export interface Penalty {
  id: string;
  label: string;
  /** Negative number. */
  points: number;
  reason: string;
  /** Optional maximum grade when this penalty applies. */
  capsGrade?: Grade;
}

export interface ScanReport {
  domain: string;
  scannedAt: string;
  durationMs: number;
  /** URL whose response headers were analysed (after redirects). */
  finalUrl: string | null;
  finalStatus: number | null;
  ip: string | null;
  score: number;
  grade: Grade;
  cap: GradeCap | null;
  counts: Record<Exclude<Status, "info">, number>;
  categories: CategoryResult[];
  /** Deductions from public threat-intel data (empty when unavailable). */
  penalties: Penalty[];
  details: ReportDetails;
  notes: string[];
}

export type IntelEvent = {
  [K in IntelSource]: { type: "intel"; source: K; data: IntelDataMap[K] | null };
}[IntelSource];

/** Events streamed (as NDJSON) from /api/scan to the browser. */
export type ScanEvent =
  | { type: "start"; domain: string; checks: CategoryId[] }
  | { type: "check"; id: CategoryId; status: Status }
  | { type: "result"; report: ScanReport }
  | IntelEvent
  | { type: "error"; message: string };

export const CATEGORY_META: Record<CategoryId, { title: string; description: string; maxScore: number }> = {
  https: {
    title: "HTTPS",
    description: "Whether the site is served over an encrypted connection and upgrades plain HTTP visitors.",
    maxScore: 12,
  },
  tls: {
    title: "TLS certificate & protocols",
    description: "Certificate validity and strength, and which TLS protocol versions the server still accepts.",
    maxScore: 22,
  },
  headers: {
    title: "Security headers",
    description: "HTTP response headers that tell browsers to enable built-in protections.",
    maxScore: 32,
  },
  cookies: {
    title: "Cookies",
    description: "Security flags on cookies set by the homepage.",
    maxScore: 8,
  },
  leakage: {
    title: "Information leakage",
    description: "Headers that reveal server software and versions to attackers, and the technologies we could detect.",
    maxScore: 5,
  },
  email: {
    title: "Email security",
    description: "DNS records that stop attackers from sending email pretending to be this domain.",
    maxScore: 12,
  },
  dns: {
    title: "DNS security",
    description: "CAA records that restrict who can issue certificates, and DNSSEC signatures on DNS answers.",
    maxScore: 6,
  },
  files: {
    title: "Public files",
    description: "security.txt for reporting vulnerabilities, and what robots.txt reveals.",
    maxScore: 3,
  },
};

export const CATEGORY_ORDER: CategoryId[] = ["https", "tls", "headers", "cookies", "leakage", "email", "dns", "files"];
