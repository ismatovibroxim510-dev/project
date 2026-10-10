import { createHash } from "node:crypto";
import { isIP } from "node:net";
import { assertPublicHostname } from "@/lib/scanner/domain";

/**
 * Validates the page a clickjacking demo may embed: an https URL on a public
 * hostname with the default port. Anything else returns null.
 */
export function parseFrameTarget(raw: string | null): URL | null {
  if (!raw || raw.length > 2048) return null;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "https:" || url.username || url.password || url.port !== "") return null;
  const host = url.hostname.replace(/^\[|\]$/g, "");
  if (isIP(host)) return null;
  try {
    assertPublicHostname(host);
  } catch {
    return null;
  }
  url.hash = "";
  return url;
}

const escapeHtml = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;").replace(/'/g, "&#39;");

const STYLE = "html,body{margin:0;height:100%;background:#fff}iframe{border:0;width:100%;height:100%;display:block}";
const STYLE_HASH = `'sha256-${createHash("sha256").update(STYLE).digest("base64")}'`;
const NOTICE_STYLE =
  "body{margin:0;display:grid;place-items:center;min-height:100vh;background:#05080f;color:#cbd5e1;font:15px/1.5 system-ui,sans-serif;text-align:center;padding:24px}";
const NOTICE_HASH = `'sha256-${createHash("sha256").update(NOTICE_STYLE).digest("base64")}'`;

const BASE_HEADERS = {
  "Content-Type": "text/html; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
  "X-Robots-Tag": "noindex",
};

/**
 * HTML for the inner demo page. Its CSP allows framing ONLY the exact scanned
 * origin, and only our own pages may embed it. The target is embedded with
 * sandbox="" (no scripts, forms, popups or navigation of the top window).
 */
export function frameDemoResponse(target: URL): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>Clickjacking demo</title><style>${STYLE}</style></head><body><iframe src="${escapeHtml(target.href)}" sandbox="" referrerpolicy="no-referrer" loading="eager" title="Preview of ${escapeHtml(target.hostname)}"></iframe></body></html>`;
  const csp = [
    "default-src 'none'",
    `style-src ${STYLE_HASH}`,
    `frame-src ${target.origin}`,
    "frame-ancestors 'self'",
    "base-uri 'none'",
    "form-action 'none'",
  ].join("; ");
  return new Response(html, {
    headers: { ...BASE_HEADERS, "Content-Security-Policy": csp, "X-Frame-Options": "SAMEORIGIN" },
  });
}

/** Shown instead of the demo when the URL is invalid or the page is opened directly. */
export function frameDemoNotice(message: string, status: number): Response {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>Clickjacking demo</title><style>${NOTICE_STYLE}</style></head><body><p>${escapeHtml(message)}</p></body></html>`;
  return new Response(html, {
    status,
    headers: {
      ...BASE_HEADERS,
      "Content-Security-Policy": `default-src 'none'; style-src ${NOTICE_HASH}; frame-ancestors 'self'; base-uri 'none'; form-action 'none'`,
      "X-Frame-Options": "SAMEORIGIN",
    },
  });
}
