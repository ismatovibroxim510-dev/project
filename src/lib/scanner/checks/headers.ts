import type { Hop } from "../net";
import type { CategoryResult, Finding } from "../types";
import { category, finding, header } from "../util";

const HALF_YEAR = 15552000;

type Directives = Map<string, string[]>;

/** Parse a header value that may contain several comma-separated CSP policies. */
export function parseCsp(value: string): Directives[] {
  return value
    .split(",")
    .map((policy) => {
      const map: Directives = new Map();
      for (const part of policy.split(";")) {
        const tokens = part.trim().split(/\s+/).filter(Boolean);
        if (!tokens.length) continue;
        const name = tokens[0].toLowerCase();
        if (!map.has(name)) map.set(name, tokens.slice(1)); // first occurrence wins, per spec
      }
      return map;
    })
    .filter((m) => m.size > 0);
}

interface CspAnalysis {
  points: number;
  issues: string[];
}

function analyzeScriptPolicy(policy: Directives): CspAnalysis {
  const sources = policy.get("script-src") ?? policy.get("default-src");
  if (!sources) {
    return {
      points: 3,
      issues: ["No script-src or default-src directive, so scripts from anywhere are still allowed."],
    };
  }
  const lower = sources.map((s) => s.toLowerCase());
  const hasNonceOrHash = lower.some((s) => /^'(nonce-|sha256-|sha384-|sha512-)/.test(s));
  const strictDynamic = lower.includes("'strict-dynamic'");
  const issues: string[] = [];
  let points = 9;
  // Browsers ignore 'unsafe-inline' when a nonce or hash is present.
  if (lower.includes("'unsafe-inline'") && !hasNonceOrHash) {
    points -= 4;
    issues.push("'unsafe-inline' allows inline scripts, which removes most of CSP's protection against XSS.");
  }
  if (lower.includes("'unsafe-eval'")) {
    points -= 2;
    issues.push("'unsafe-eval' lets scripts turn strings into code with eval().");
  }
  if (!strictDynamic && lower.some((s) => s === "*" || s === "http:" || s === "https:" || s === "data:")) {
    points -= 3;
    issues.push("A wildcard or scheme-only source (*, https:, data:) allows scripts from almost any origin.");
  }
  return { points: Math.max(points, 2), issues };
}

const CSP_FIX =
  "Start with a policy like `default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'` and add the specific origins you need. Roll it out safely with Content-Security-Policy-Report-Only first. For inline scripts, use nonces or hashes instead of 'unsafe-inline'.";

function checkCsp(hop: Hop): { finding: Finding; frameAncestors: boolean } {
  const base = {
    id: "csp",
    title: "Content-Security-Policy",
    maxPoints: 9,
    explanation:
      "CSP tells the browser which scripts, styles and other resources are allowed to load. It is the strongest defence against cross-site scripting (XSS): even if an attacker injects a <script>, the browser refuses to run it.",
  };
  const value = header(hop.headers, "content-security-policy");
  const reportOnly = header(hop.headers, "content-security-policy-report-only");

  if (!value) {
    if (reportOnly) {
      return {
        frameAncestors: false,
        finding: finding({
          ...base,
          status: "warn",
          points: 2,
          summary: "Only Content-Security-Policy-Report-Only is set: violations are reported but not blocked.",
          fix: "Once the report-only policy produces no unexpected violations, send the same policy as Content-Security-Policy to enforce it.",
          evidence: reportOnly,
        }),
      };
    }
    return {
      frameAncestors: false,
      finding: finding({ ...base, status: "fail", points: 0, summary: "Header is missing.", fix: CSP_FIX }),
    };
  }

  const policies = parseCsp(value);
  const frameAncestors = policies.some((p) => p.has("frame-ancestors"));
  // Every policy is enforced, so the strictest one decides what scripts can run.
  const analysis = policies
    .map(analyzeScriptPolicy)
    .reduce<CspAnalysis>((best, a) => (a.points > best.points ? a : best), { points: 0, issues: [] });
  const ok = analysis.points >= 9;
  return {
    frameAncestors,
    finding: finding({
      ...base,
      status: ok ? "pass" : "warn",
      points: analysis.points,
      summary: ok ? "A policy is set and restricts which scripts can run." : analysis.issues.join(" "),
      fix: ok ? undefined : CSP_FIX,
      evidence: value,
    }),
  };
}

function checkHsts(hop: Hop, isHttps: boolean): Finding {
  const base = {
    id: "hsts",
    title: "Strict-Transport-Security (HSTS)",
    maxPoints: 7,
    explanation:
      "HSTS tells browsers to always use HTTPS for this site, even if someone types http:// or clicks an old link. This blocks SSL-stripping attacks on public Wi-Fi.",
  };
  const fix =
    "Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` on HTTPS responses. Once you're sure every subdomain supports HTTPS, add `preload` and submit the domain at hstspreload.org.";
  if (!isHttps) {
    return finding({
      ...base,
      status: "fail",
      points: 0,
      summary: "Not applicable: the site isn't served over HTTPS.",
      fix: "Enable HTTPS first, then add HSTS.",
    });
  }
  const value = header(hop.headers, "strict-transport-security");
  if (!value) return finding({ ...base, status: "fail", points: 0, summary: "Header is missing.", fix });

  // Browsers only honour the first HSTS header.
  const first = hop.headers["strict-transport-security"][0];
  const directives = first.split(";").map((d) => d.trim().toLowerCase());
  const maxAgeRaw = directives.find((d) => d.startsWith("max-age"));
  const maxAgeMatch = maxAgeRaw?.match(/^max-age\s*=\s*"?(\d+)"?$/);
  if (!maxAgeMatch) {
    return finding({
      ...base,
      status: "fail",
      points: 0,
      summary: "Header is present but has no valid max-age, so browsers ignore it.",
      fix,
      evidence: value,
    });
  }
  const maxAge = Number(maxAgeMatch[1]);
  const days = Math.floor(maxAge / 86400);
  const extras = [
    directives.includes("includesubdomains") ? "includeSubDomains" : null,
    directives.includes("preload") ? "preload" : null,
  ].filter(Boolean);
  const extrasText = extras.length ? ` with ${extras.join(" and ")}` : "";
  if (maxAge === 0) {
    return finding({
      ...base,
      status: "fail",
      points: 0,
      summary: "max-age=0 tells browsers to forget the HSTS policy.",
      fix,
      evidence: value,
    });
  }
  if (maxAge < HALF_YEAR) {
    return finding({
      ...base,
      status: "warn",
      points: 3,
      summary: `max-age is only ${days} day${days === 1 ? "" : "s"}${extrasText}. At least 180 days is recommended.`,
      fix,
      evidence: value,
    });
  }
  return finding({
    ...base,
    status: "pass",
    points: 7,
    summary: `Enabled for ${days} days${extrasText}.`,
    fix: extras.includes("includeSubDomains")
      ? undefined
      : "Optional: add includeSubDomains so every subdomain is also protected.",
    evidence: value,
  });
}

function checkFrameOptions(hop: Hop, cspFrameAncestors: boolean): Finding {
  const base = {
    id: "x-frame-options",
    title: "X-Frame-Options",
    maxPoints: 5,
    explanation:
      "Stops other websites from embedding this site in an invisible frame and tricking users into clicking buttons (clickjacking).",
  };
  const fix =
    "Send `X-Frame-Options: DENY` (or SAMEORIGIN if you frame your own pages), or the modern equivalent `Content-Security-Policy: frame-ancestors 'none'`.";
  const value = header(hop.headers, "x-frame-options");
  const v = value?.split(",")[0].trim().toUpperCase();
  if (v === "DENY" || v === "SAMEORIGIN") {
    return finding({ ...base, status: "pass", points: 5, summary: `Set to ${v}.`, evidence: value });
  }
  if (cspFrameAncestors) {
    return finding({
      ...base,
      status: "pass",
      points: 5,
      summary: value
        ? "Protected by the CSP frame-ancestors directive (which overrides X-Frame-Options)."
        : "Header is missing, but the CSP frame-ancestors directive provides the same protection.",
      evidence: value,
    });
  }
  if (v?.startsWith("ALLOW-FROM")) {
    return finding({
      ...base,
      status: "warn",
      points: 2,
      summary: "ALLOW-FROM is obsolete and ignored by modern browsers, so the site can be framed.",
      fix: "Use `Content-Security-Policy: frame-ancestors https://allowed.example` instead.",
      evidence: value,
    });
  }
  if (value) {
    return finding({
      ...base,
      status: "fail",
      points: 0,
      summary: `Invalid value "${value}"; browsers ignore it.`,
      fix,
      evidence: value,
    });
  }
  return finding({
    ...base,
    status: "fail",
    points: 0,
    summary: "Header is missing and there is no CSP frame-ancestors directive.",
    fix,
  });
}

function checkContentTypeOptions(hop: Hop): Finding {
  const base = {
    id: "x-content-type-options",
    title: "X-Content-Type-Options",
    maxPoints: 5,
    explanation:
      'Stops browsers from "guessing" a file\'s type. Without it, an uploaded file that looks like text could be run as a script.',
  };
  const fix = "Send `X-Content-Type-Options: nosniff` on every response.";
  const value = header(hop.headers, "x-content-type-options");
  if (value?.split(",")[0].trim().toLowerCase() === "nosniff") {
    return finding({ ...base, status: "pass", points: 5, summary: "Set to nosniff.", evidence: value });
  }
  if (value)
    return finding({
      ...base,
      status: "fail",
      points: 0,
      summary: `Invalid value "${value}"; the only valid value is nosniff.`,
      fix,
      evidence: value,
    });
  return finding({ ...base, status: "fail", points: 0, summary: "Header is missing.", fix });
}

const STRICT_REFERRER = new Set(["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"]);
const WEAK_REFERRER = new Set(["origin", "origin-when-cross-origin", "no-referrer-when-downgrade"]);

function checkReferrerPolicy(hop: Hop): Finding {
  const base = {
    id: "referrer-policy",
    title: "Referrer-Policy",
    maxPoints: 3,
    explanation:
      "Controls how much of the current URL is shared with other sites when users click links. Full URLs can leak private paths, search terms or tokens.",
  };
  const fix = "Send `Referrer-Policy: strict-origin-when-cross-origin` (or `no-referrer` for maximum privacy).";
  const value = header(hop.headers, "referrer-policy");
  if (!value) {
    return finding({
      ...base,
      status: "warn",
      points: 1,
      summary: "Header is missing. Modern browsers default to a reasonable policy, but older ones leak full URLs.",
      fix,
    });
  }
  // With a list, browsers use the last value they understand.
  const tokens = value.split(",").map((t) => t.trim().toLowerCase());
  const effective = [...tokens]
    .reverse()
    .find((t) => STRICT_REFERRER.has(t) || WEAK_REFERRER.has(t) || t === "unsafe-url");
  if (effective && STRICT_REFERRER.has(effective)) {
    return finding({ ...base, status: "pass", points: 3, summary: `Set to ${effective}.`, evidence: value });
  }
  if (effective === "unsafe-url") {
    return finding({
      ...base,
      status: "fail",
      points: 0,
      summary: "unsafe-url sends the full URL (including path and query) to every site, even over plain HTTP.",
      fix,
      evidence: value,
    });
  }
  if (effective) {
    return finding({
      ...base,
      status: "warn",
      points: 1,
      summary: `${effective} shares more information than necessary.`,
      fix,
      evidence: value,
    });
  }
  return finding({
    ...base,
    status: "warn",
    points: 1,
    summary: "No recognised policy value, so browsers fall back to their default.",
    fix,
    evidence: value,
  });
}

function checkPermissionsPolicy(hop: Hop): Finding {
  const base = {
    id: "permissions-policy",
    title: "Permissions-Policy",
    maxPoints: 3,
    explanation:
      "Turns off powerful browser features (camera, microphone, location...) that the site doesn't use, so injected scripts or embedded third parties can't abuse them.",
  };
  const fix =
    "Send e.g. `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()` listing the features you don't need.";
  const value = header(hop.headers, "permissions-policy");
  if (value && value.includes("=")) {
    return finding({ ...base, status: "pass", points: 3, summary: "A policy is set.", evidence: value });
  }
  if (value) {
    return finding({
      ...base,
      status: "warn",
      points: 1,
      summary: "Header is present but doesn't look valid.",
      fix,
      evidence: value,
    });
  }
  const legacy = header(hop.headers, "feature-policy");
  if (legacy) {
    return finding({
      ...base,
      status: "warn",
      points: 1,
      summary: "Only the deprecated Feature-Policy header is set.",
      fix: `Replace Feature-Policy with Permissions-Policy. ${fix}`,
      evidence: legacy,
    });
  }
  return finding({ ...base, status: "warn", points: 0, summary: "Header is missing.", fix });
}

export function checkHeaders(hop: Hop): CategoryResult {
  const isHttps = hop.url.startsWith("https:");
  const csp = checkCsp(hop);
  return category("headers", [
    checkHsts(hop, isHttps),
    csp.finding,
    checkFrameOptions(hop, csp.frameAncestors),
    checkContentTypeOptions(hop),
    checkReferrerPolicy(hop),
    checkPermissionsPolicy(hop),
  ]);
}
