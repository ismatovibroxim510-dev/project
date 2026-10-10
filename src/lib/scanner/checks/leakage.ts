import type { Hop } from "../net";
import type { CategoryResult, Finding, Technology } from "../types";
import { category, finding, header } from "../util";

/** Matches version numbers like "1.18.0", "10.0", "v8.1" - not plain names like "cloudflare". */
const VERSION_RE = /\bv?\d+\.\d+/i;

export function checkLeakage(hop: Hop, technologies: Technology[]): CategoryResult {
  const server = header(hop.headers, "server");
  const serverExplanation =
    "The Server header names the web server software. Including an exact version lets attackers instantly look up known vulnerabilities for that version.";
  const serverFinding =
    server && VERSION_RE.test(server)
      ? finding({
          id: "server-header",
          title: "Server header",
          status: "fail",
          points: 0,
          maxPoints: 3,
          summary: `Reveals software version: "${server}".`,
          explanation: serverExplanation,
          fix: 'Hide the version. Nginx: `server_tokens off;`. Apache: `ServerTokens Prod` and `ServerSignature Off`. IIS: remove the header with URL Rewrite or `removeServerHeader="true"`.',
          evidence: server,
        })
      : finding({
          id: "server-header",
          title: "Server header",
          status: "pass",
          points: 3,
          maxPoints: 3,
          summary: server ? `Present ("${server}") but does not include a version number.` : "Not present.",
          explanation: serverExplanation,
          evidence: server,
        });

  const leaky = ["x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator"]
    .map((name) => ({ name, value: header(hop.headers, name) }))
    .filter((h): h is { name: string; value: string } => !!h.value);
  const evidence = leaky.map((h) => `${h.name}: ${h.value}`).join("\n");
  const poweredExplanation =
    "Headers like X-Powered-By advertise the framework or language behind the site (e.g. PHP/8.1, Express, ASP.NET). That information helps attackers pick exploits and adds nothing for visitors.";
  const poweredFix =
    "Remove these headers. Express: `app.disable('x-powered-by')`. PHP: `expose_php = Off` in php.ini. Next.js: `poweredByHeader: false`. ASP.NET: `<httpRuntime enableVersionHeader=\"false\" />` and remove X-Powered-By in web.config.";

  let poweredFinding;
  if (!leaky.length) {
    poweredFinding = finding({
      id: "powered-by",
      title: "X-Powered-By and similar headers",
      status: "pass",
      points: 2,
      maxPoints: 2,
      summary: "No technology-revealing headers found.",
      explanation: poweredExplanation,
    });
  } else if (leaky.some((h) => VERSION_RE.test(h.value))) {
    poweredFinding = finding({
      id: "powered-by",
      title: "X-Powered-By and similar headers",
      status: "fail",
      points: 0,
      maxPoints: 2,
      summary: `Reveals technology and version: ${leaky.map((h) => h.name).join(", ")}.`,
      explanation: poweredExplanation,
      fix: poweredFix,
      evidence,
    });
  } else {
    poweredFinding = finding({
      id: "powered-by",
      title: "X-Powered-By and similar headers",
      status: "warn",
      points: 1,
      maxPoints: 2,
      summary: `Reveals the technology stack: ${leaky.map((h) => h.name).join(", ")}.`,
      explanation: poweredExplanation,
      fix: poweredFix,
      evidence,
    });
  }

  return category("leakage", [serverFinding, poweredFinding, techFinding(technologies)]);
}

function techFinding(technologies: Technology[]): Finding {
  const versioned = technologies.filter((t) => t.version);
  const list = technologies.map((t) => `${t.name}${t.version ? ` ${t.version}` : ""}`);
  return finding({
    id: "technologies",
    title: "Detected technologies",
    status: "info",
    points: 0,
    maxPoints: 0,
    summary: technologies.length
      ? `${list.join(", ")}.${versioned.length ? ` Version numbers are exposed for ${versioned.map((t) => t.name).join(", ")}.` : ""}`
      : "No technologies could be identified from headers or cookie names.",
    explanation:
      "Identified passively from response headers and cookie names (cookie values are never read). Knowing the stack isn't a vulnerability by itself, but exposed version numbers let attackers match the site against lists of known vulnerabilities. This is informational; version leaks are scored above.",
    evidence: technologies
      .map((t) => `${t.name}${t.version ? ` ${t.version}` : ""} (${t.category}, from ${t.source})`)
      .join("\n"),
  });
}
