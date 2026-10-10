import { fetchChain, type ChainResult } from "../net";
import type { CategoryResult, Finding, RobotsDetails } from "../types";
import { category, finding, header } from "../util";

export const SECURITY_TXT_MAX_BYTES = 32 * 1024;
export const ROBOTS_MAX_BYTES = 64 * 1024;
const ROBOTS_DISPLAY_LIMIT = 60;

/** A real text file: 200 OK, text/plain, body read within the size limit. HTML "soft 404" pages don't count. */
export function plainTextBody(chain: ChainResult): { body: string | null; reason: string } {
  const hop = chain.hops.at(-1);
  if (!hop) return { body: null, reason: chain.error ?? chain.stoppedReason ?? "no response" };
  if (hop.status !== 200) return { body: null, reason: `HTTP ${hop.status}` };
  const type = (header(hop.headers, "content-type") ?? "").toLowerCase();
  if (!type.startsWith("text/plain"))
    return { body: null, reason: `served as ${type || "unknown type"}, not text/plain` };
  if (hop.bodyTooLarge) return { body: null, reason: "file is larger than the size limit" };
  return { body: hop.body ?? "", reason: "" };
}

export interface SecurityTxt {
  contact: string[];
  expires: string | null;
  fields: number;
}

export function parseSecurityTxt(text: string): SecurityTxt {
  const contact: string[] = [];
  let expires: string | null = null;
  let fields = 0;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^([A-Za-z-]+):\s*(.+)$/.exec(line);
    if (!m) continue;
    fields++;
    const key = m[1].toLowerCase();
    if (key === "contact") contact.push(m[2].trim());
    else if (key === "expires" && expires === null) expires = m[2].trim();
  }
  return { contact, expires, fields };
}

export function securityTxtFinding(result: { body: string | null; reason: string }, now = new Date()): Finding {
  const base = {
    id: "security-txt",
    title: "security.txt",
    maxPoints: 3,
    explanation:
      "/.well-known/security.txt (RFC 9116) tells security researchers how to report a vulnerability they found. Without it, reports often get lost or go unsent.",
  };
  const fix =
    "Publish a plain-text file at `/.well-known/security.txt` with at least a `Contact:` (email or URL) and an `Expires:` date less than a year ahead. securitytxt.org can generate one.";
  if (result.body === null) {
    return finding({ ...base, status: "warn", points: 0, summary: `No security.txt found (${result.reason}).`, fix });
  }
  const parsed = parseSecurityTxt(result.body);
  const evidence = result.body.slice(0, 600);
  const problems: string[] = [];
  let expired = false;
  if (!parsed.contact.length) problems.push("it has no Contact field");
  if (!parsed.expires) problems.push("it has no Expires field");
  else {
    const date = new Date(parsed.expires);
    if (Number.isNaN(date.getTime())) problems.push("its Expires date isn't a valid date");
    else if (date < now) {
      expired = true;
      problems.push(`it expired on ${date.toISOString().slice(0, 10)}`);
    }
  }
  if (!problems.length) {
    return finding({
      ...base,
      status: "pass",
      points: 3,
      summary: `Published with contact ${parsed.contact[0]}, valid until ${new Date(parsed.expires!).toISOString().slice(0, 10)}.`,
      evidence,
    });
  }
  return finding({
    ...base,
    status: "warn",
    points: parsed.contact.length && !expired ? 2 : 1,
    summary: `security.txt exists, but ${problems.join(" and ")}.`,
    fix: expired ? "Update the Expires date (keep it under a year ahead) and review the contact details." : fix,
    evidence,
  });
}

const SENSITIVE_WORD =
  /(^|[/._-])(admin|administrator|backups?|bak|private|staging|stage|config|configuration|secrets?|internal|dump|phpmyadmin|db|database|old|tmp|logs?)([/._-]|$)/i;
const SENSITIVE_EXT = /\.(git|svn|env|sql|bak|config|ini|log)\b|\.ht(access|passwd)/i;

/** Default entries every WordPress site has; flagging them would just be noise. */
const WELL_KNOWN = /^\/wp-admin\/?$/i;

export function isSensitivePath(path: string): boolean {
  if (WELL_KNOWN.test(path)) return false;
  return SENSITIVE_WORD.test(path) || SENSITIVE_EXT.test(path);
}

/** Parse Disallow rules (for every user-agent). The listed paths are only displayed, never requested. */
export function parseRobots(text: string): RobotsDetails {
  const disallow = new Set<string>();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/#.*/, "").trim();
    const m = /^disallow\s*:\s*(\S+)/i.exec(line);
    if (m) disallow.add(m[1].slice(0, 200));
  }
  const all = [...disallow];
  const sensitive = all.filter(isSensitivePath);
  return {
    found: true,
    total: all.length,
    // Show sensitive paths first so they're never cut off by the display limit.
    disallow: [...sensitive, ...all.filter((p) => !sensitive.includes(p))].slice(0, ROBOTS_DISPLAY_LIMIT),
    sensitive: sensitive.slice(0, ROBOTS_DISPLAY_LIMIT),
  };
}

export function robotsFinding(result: { body: string | null; reason: string }): {
  finding: Finding;
  details: RobotsDetails;
} {
  const base = {
    id: "robots-txt",
    title: "robots.txt",
    maxPoints: 0,
    points: 0,
    explanation:
      "robots.txt asks search engines not to crawl certain paths. It's public, and it is not access control: anyone can read it, and attackers often check it for hidden admin panels or backups. Listing a secret path there advertises it. This check is informational and doesn't affect the score; we never visit the listed paths.",
  };
  if (result.body === null) {
    return {
      details: { found: false, disallow: [], sensitive: [], total: 0 },
      finding: finding({ ...base, status: "info", summary: `No robots.txt found (${result.reason}).` }),
    };
  }
  const details = parseRobots(result.body);
  if (details.sensitive.length) {
    return {
      details,
      finding: finding({
        ...base,
        status: "warn",
        summary: `${details.total} disallowed path${details.total === 1 ? "" : "s"}, ${details.sensitive.length} of which look sensitive: ${details.sensitive.slice(0, 4).join(", ")}${details.sensitive.length > 4 ? ", …" : ""}.`,
        fix: "Don't rely on robots.txt to hide anything. Protect sensitive paths with authentication or IP restrictions (or remove them from the public server), and drop them from robots.txt so they aren't advertised.",
        evidence: details.sensitive.join("\n"),
      }),
    };
  }
  return {
    details,
    finding: finding({
      ...base,
      status: "info",
      summary: details.total
        ? `${details.total} disallowed path${details.total === 1 ? "" : "s"}; none look sensitive.`
        : "Found, with no Disallow rules.",
    }),
  };
}

export function fetchSecurityTxt(host: string): Promise<ChainResult> {
  // RFC 9116 requires HTTPS for security.txt.
  return fetchChain(`https://${host}/.well-known/security.txt`, { maxBodyBytes: SECURITY_TXT_MAX_BYTES });
}

export function fetchRobots(host: string, scheme: "https" | "http"): Promise<ChainResult> {
  return fetchChain(`${scheme}://${host}/robots.txt`, { maxBodyBytes: ROBOTS_MAX_BYTES });
}

export function checkFiles(
  securityTxt: ChainResult,
  robots: ChainResult,
): { category: CategoryResult; robots: RobotsDetails } {
  const robotsResult = robotsFinding(plainTextBody(robots));
  return {
    category: category("files", [securityTxtFinding(plainTextBody(securityTxt)), robotsResult.finding]),
    robots: robotsResult.details,
  };
}
