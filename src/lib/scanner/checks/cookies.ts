import type { Hop } from "../net";
import type { CategoryResult, Finding } from "../types";
import { category, finding } from "../util";

export interface ParsedCookie {
  name: string;
  secure: boolean;
  httpOnly: boolean;
  sameSite: string | null;
}

/** Parse Set-Cookie headers. Cookie VALUES are deliberately discarded and never reported. */
export function parseSetCookie(line: string): ParsedCookie | null {
  const [pair, ...attrs] = line.split(";");
  const eq = pair.indexOf("=");
  const name = (eq === -1 ? pair : pair.slice(0, eq)).trim();
  if (!name) return null;
  let secure = false;
  let httpOnly = false;
  let sameSite: string | null = null;
  for (const attr of attrs) {
    const [k, ...v] = attr.split("=");
    const key = k.trim().toLowerCase();
    if (key === "secure") secure = true;
    else if (key === "httponly") httpOnly = true;
    else if (key === "samesite") sameSite = v.join("=").trim().toLowerCase() || null;
  }
  return { name: name.slice(0, 64), secure, httpOnly, sameSite };
}

function proportional(max: number, ok: number, total: number) {
  return Math.round((max * ok * 10) / total) / 10;
}

export function checkCookies(hops: Hop[]): CategoryResult {
  // Collect cookies from every response in the homepage redirect chain; later ones win.
  const byName = new Map<string, ParsedCookie>();
  for (const hop of hops) {
    for (const line of hop.headers["set-cookie"] ?? []) {
      const c = parseSetCookie(line);
      if (c) byName.set(c.name, c);
    }
  }
  const cookies = [...byName.values()];
  const isHttps = hops.at(-1)?.url.startsWith("https:") ?? false;

  if (cookies.length === 0) {
    return category("cookies", [
      finding({
        id: "cookies-none",
        title: "Cookie flags",
        status: "pass",
        points: 8,
        maxPoints: 8,
        summary: "The homepage doesn't set any cookies, so there's nothing to misconfigure.",
        explanation:
          "Cookies often hold session IDs. The Secure, HttpOnly and SameSite flags protect them from being stolen or misused. Pages behind a login may still set cookies we can't see.",
      }),
    ]);
  }

  const describe = (c: ParsedCookie) =>
    `${c.name}: ${[c.secure ? "Secure" : "no Secure", c.httpOnly ? "HttpOnly" : "no HttpOnly", c.sameSite ? `SameSite=${c.sameSite}` : "no SameSite"].join(", ")}`;
  const evidence =
    cookies.slice(0, 20).map(describe).join("\n") + (cookies.length > 20 ? `\n…and ${cookies.length - 20} more` : "");
  const total = cookies.length;
  const list = (cs: ParsedCookie[]) =>
    cs
      .slice(0, 6)
      .map((c) => c.name)
      .join(", ") + (cs.length > 6 ? ", …" : "");
  const findings: Finding[] = [];

  // Secure (5)
  const insecure = cookies.filter((c) => !c.secure);
  findings.push(
    finding({
      id: "cookie-secure",
      title: "Secure flag",
      maxPoints: 4,
      points: proportional(4, total - insecure.length, total),
      status: insecure.length === 0 ? "pass" : insecure.length < total ? "warn" : "fail",
      summary:
        insecure.length === 0
          ? `All ${total} cookie${total === 1 ? " is" : "s are"} marked Secure.`
          : `${insecure.length} of ${total} cookie${total === 1 ? "" : "s"} missing Secure: ${list(insecure)}.`,
      explanation:
        "Secure cookies are only ever sent over HTTPS. Without the flag, a cookie can leak over an unencrypted connection and be stolen by anyone on the network.",
      fix:
        insecure.length === 0
          ? undefined
          : `Add the Secure attribute to every cookie${isHttps ? "" : " (and serve the site over HTTPS)"}, e.g. \`Set-Cookie: session=...; Secure; HttpOnly; SameSite=Lax\`.`,
      evidence,
    }),
  );

  // HttpOnly (3) - some cookies legitimately need JS access, so this caps at warn.
  const scriptReadable = cookies.filter((c) => !c.httpOnly);
  findings.push(
    finding({
      id: "cookie-httponly",
      title: "HttpOnly flag",
      maxPoints: 2,
      points: proportional(2, total - scriptReadable.length, total),
      status: scriptReadable.length === 0 ? "pass" : "warn",
      summary:
        scriptReadable.length === 0
          ? `All ${total} cookie${total === 1 ? " is" : "s are"} HttpOnly.`
          : `${scriptReadable.length} of ${total} cookie${total === 1 ? "" : "s"} readable by JavaScript: ${list(scriptReadable)}.`,
      explanation:
        "HttpOnly cookies can't be read by JavaScript, so an XSS attack can't steal them. Session and authentication cookies should always be HttpOnly; preference or analytics cookies sometimes need JS access.",
      fix:
        scriptReadable.length === 0
          ? undefined
          : "Add HttpOnly to every cookie that page scripts don't need to read - especially session and login cookies.",
    }),
  );

  // SameSite (2). SameSite=None without Secure is rejected by browsers.
  const badSameSite = cookies.filter((c) => !c.sameSite || (c.sameSite === "none" && !c.secure));
  findings.push(
    finding({
      id: "cookie-samesite",
      title: "SameSite attribute",
      maxPoints: 2,
      points: proportional(2, total - badSameSite.length, total),
      status: badSameSite.length === 0 ? "pass" : "warn",
      summary:
        badSameSite.length === 0
          ? `All ${total} cookie${total === 1 ? " has" : "s have"} a SameSite attribute.`
          : `${badSameSite.length} of ${total} cookie${total === 1 ? "" : "s"} without a valid SameSite setting: ${list(badSameSite)}.`,
      explanation:
        "SameSite controls whether a cookie is sent when another website links to or submits a form to this site. Lax or Strict blocks most cross-site request forgery (CSRF) attacks.",
      fix:
        badSameSite.length === 0
          ? undefined
          : "Set `SameSite=Lax` (or Strict) explicitly. Only use SameSite=None for cookies that truly need cross-site use, and always together with Secure.",
    }),
  );

  return category("cookies", findings);
}
