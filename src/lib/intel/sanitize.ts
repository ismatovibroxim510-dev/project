/** Helpers for turning untrusted third-party JSON into small, plain-text values. */

/** Strip control characters, collapse whitespace and cap the length. Returns null for non-strings/empty. */
export function text(value: unknown, max = 200): string | null {
  if (typeof value !== "string") return null;
  const cleaned = value
    .replace(/[\u0000-\u001f\u007f-\u009f​-‏‪-‮⁦-⁩]/g, " ")
    .replace(/\s+/g, " ")
    .trim();
  if (!cleaned) return null;
  return cleaned.length > max ? `${cleaned.slice(0, max - 1)}…` : cleaned;
}

export function finiteNumber(value: unknown, min = -Infinity, max = Infinity): number | null {
  return typeof value === "number" && Number.isFinite(value) && value >= min && value <= max ? value : null;
}

/** ISO-ish date string -> normalized ISO string, or null. */
export function isoDate(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 40) return null;
  const t = Date.parse(value);
  if (Number.isNaN(t)) return null;
  const year = new Date(t).getUTCFullYear();
  return year >= 1980 && year <= 2200 ? new Date(t).toISOString() : null;
}

export function stringList(value: unknown, maxItems: number, maxLength = 100, pattern?: RegExp): string[] {
  if (!Array.isArray(value)) return [];
  const out: string[] = [];
  for (const v of value) {
    const t = text(v, maxLength);
    if (t && (!pattern || pattern.test(t)) && !out.includes(t)) out.push(t);
    if (out.length >= maxItems) break;
  }
  return out;
}

const ENTITIES: Record<string, string> = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

/**
 * HTML -> plain text. Removes script/style blocks and all tags, then decodes
 * entities. The result is still rendered as a text node, so this is about
 * readability, not the only line of defence.
 */
export function stripHtml(html: unknown, max = 600): string | null {
  if (typeof html !== "string") return null;
  const withoutBlocks = html.replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, " ");
  const withoutTags = withoutBlocks.replace(/<\/?[a-z!][^>]*>/gi, " ").replace(/[<>]/g, " ");
  const decoded = withoutTags.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, code: string) => {
    if (code[0] === "#") {
      const n = code[1].toLowerCase() === "x" ? parseInt(code.slice(2), 16) : parseInt(code.slice(1), 10);
      return n > 0 && n < 0x110000 ? String.fromCodePoint(n) : " ";
    }
    return ENTITIES[code.toLowerCase()] ?? m;
  });
  // Decoding can produce new "<"; tags are already gone, so remove brackets once more for tidiness.
  return text(decoded.replace(/[<>]/g, ""), max);
}

/**
 * Approximate registrable domain (eTLD+1) without shipping the Public Suffix List:
 * strips subdomains, keeping 3 labels for common two-part suffixes like co.uk.
 */
const TWO_PART_SUFFIXES = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "me.uk",
  "net.uk",
  "ltd.uk",
  "plc.uk",
  "com.au",
  "net.au",
  "org.au",
  "edu.au",
  "gov.au",
  "co.nz",
  "org.nz",
  "govt.nz",
  "co.jp",
  "or.jp",
  "ne.jp",
  "ac.jp",
  "go.jp",
  "com.br",
  "net.br",
  "org.br",
  "gov.br",
  "co.in",
  "net.in",
  "org.in",
  "gov.in",
  "ac.in",
  "co.za",
  "org.za",
  "gov.za",
  "com.cn",
  "net.cn",
  "org.cn",
  "gov.cn",
  "com.hk",
  "com.tw",
  "com.sg",
  "com.my",
  "com.mx",
  "com.ar",
  "com.tr",
  "gov.tr",
  "com.ua",
  "co.il",
  "co.kr",
  "or.kr",
  "com.pl",
  "co.id",
  "or.id",
  "com.ph",
  "com.vn",
  "com.sa",
  "com.eg",
  "com.pk",
  "com.ng",
  "co.ke",
  "com.co",
]);

export function registrableDomain(host: string): string {
  const labels = host.toLowerCase().replace(/\.$/, "").split(".");
  if (labels.length <= 2) return labels.join(".");
  const lastTwo = labels.slice(-2).join(".");
  return labels.slice(TWO_PART_SUFFIXES.has(lastTwo) ? -3 : -2).join(".");
}
