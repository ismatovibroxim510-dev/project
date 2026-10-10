import type { Finding, ScanReport } from "@/lib/scanner/types";

/**
 * Turns a scan report into copy-paste configuration for common platforms.
 * Only things the scan found missing or weak are included. Everything here is
 * plain text that the UI renders as text, never as HTML.
 */

export type Platform = "nginx" | "apache" | "vercel" | "netlify" | "cloudflare" | "nextjs";

export const PLATFORMS: Array<{ id: Platform; label: string }> = [
  { id: "nginx", label: "nginx" },
  { id: "apache", label: "Apache" },
  { id: "vercel", label: "Vercel" },
  { id: "netlify", label: "Netlify" },
  { id: "cloudflare", label: "Cloudflare" },
  { id: "nextjs", label: "Next.js" },
];

export interface Snippet {
  filename: string;
  language: "nginx" | "apache" | "json" | "text" | "ts" | "dns";
  code: string;
}

export interface PlatformFix {
  snippets: Snippet[];
  /** Things that can't be expressed as config on this platform, or need extra context. */
  notes: string[];
}

export type FindingFix =
  | { kind: "platform"; warning?: string; byPlatform: Record<Platform, PlatformFix> }
  | { kind: "generic"; warning?: string; snippets: Snippet[]; notes: string[] };

export interface FixBundle {
  byFinding: Record<string, FindingFix>;
  /** Every web-server fix merged into one config per platform. */
  combined: Record<Platform, PlatformFix>;
  /** Every DNS change in one zone-file snippet. */
  dns: { snippets: Snippet[]; notes: string[] };
  /** Shown above the combined view (e.g. the CSP testing warning). */
  combinedWarning?: string;
  hasAny: boolean;
}

export const STARTER_CSP =
  "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'; upgrade-insecure-requests";

export const CSP_WARNING =
  "Test before enforcing: this starter policy only allows resources from your own domain, so third-party scripts, analytics, fonts, chat widgets and embeds will be blocked until you add their origins. Deploy it first under the header name Content-Security-Policy-Report-Only, watch the browser console for violations, adjust, then switch to Content-Security-Policy.";

const HEADER_RECOMMENDATIONS: Record<string, { name: string; value: string }> = {
  hsts: { name: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" },
  csp: { name: "Content-Security-Policy", value: STARTER_CSP },
  "x-frame-options": { name: "X-Frame-Options", value: "SAMEORIGIN" },
  "x-content-type-options": { name: "X-Content-Type-Options", value: "nosniff" },
  "referrer-policy": { name: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
  "permissions-policy": {
    name: "Permissions-Policy",
    value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()",
  },
};

const LEAKY_HEADERS = ["X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"];

/** What a set of findings requires from the web server / host. */
interface Needs {
  host: string;
  emailDomain: string;
  headers: Array<{ name: string; value: string }>;
  removeHeaders: string[];
  hideServerVersion: boolean;
  httpsRedirect: boolean;
  cookieFlags: { secure: boolean; httpOnly: boolean; sameSite: boolean };
  modernTls: boolean;
  securityTxt: string | null;
  certificate: "missing" | "renew" | "rekey" | null;
}

function emptyNeeds(host: string, emailDomain: string): Needs {
  return {
    host,
    emailDomain,
    headers: [],
    removeHeaders: [],
    hideServerVersion: false,
    httpsRedirect: false,
    cookieFlags: { secure: false, httpOnly: false, sameSite: false },
    modernTls: false,
    securityTxt: null,
    certificate: null,
  };
}

function hasNeeds(n: Needs): boolean {
  return (
    n.headers.length > 0 ||
    n.removeHeaders.length > 0 ||
    n.hideServerVersion ||
    n.httpsRedirect ||
    n.cookieFlags.secure ||
    n.cookieFlags.httpOnly ||
    n.cookieFlags.sameSite ||
    n.modernTls ||
    n.securityTxt !== null ||
    n.certificate !== null
  );
}

function mergeNeeds(a: Needs, b: Needs): Needs {
  const headers = [...a.headers];
  for (const h of b.headers) if (!headers.some((x) => x.name === h.name)) headers.push(h);
  return {
    ...a,
    headers,
    removeHeaders: [...new Set([...a.removeHeaders, ...b.removeHeaders])],
    hideServerVersion: a.hideServerVersion || b.hideServerVersion,
    httpsRedirect: a.httpsRedirect || b.httpsRedirect,
    cookieFlags: {
      secure: a.cookieFlags.secure || b.cookieFlags.secure,
      httpOnly: a.cookieFlags.httpOnly || b.cookieFlags.httpOnly,
      sameSite: a.cookieFlags.sameSite || b.cookieFlags.sameSite,
    },
    modernTls: a.modernTls || b.modernTls,
    securityTxt: a.securityTxt ?? b.securityTxt,
    certificate: a.certificate ?? b.certificate,
  };
}

export function securityTxtContent(host: string, emailDomain: string, now: Date): string {
  const expires = new Date(Date.UTC(now.getUTCFullYear() + 1, now.getUTCMonth(), now.getUTCDate()));
  return [
    `Contact: mailto:security@${emailDomain}`,
    `Expires: ${expires.toISOString().replace(".000Z", "Z")}`,
    "Preferred-Languages: en",
    `Canonical: https://${host}/.well-known/security.txt`,
  ].join("\n");
}

const needsAttention = (f: Finding | undefined) => !!f && (f.status === "fail" || f.status === "warn");

/** Which response headers the powered-by finding saw (parsed from "name: value" evidence lines). */
function leakedHeaderNames(f: Finding): string[] {
  const seen = (f.evidence ?? "")
    .split("\n")
    .map((l) => l.split(":")[0].trim().toLowerCase())
    .filter(Boolean);
  const names = LEAKY_HEADERS.filter((h) => seen.includes(h.toLowerCase()));
  return names.length ? names : ["X-Powered-By"];
}

function needsForFinding(f: Finding, base: Needs, now: Date): Needs | null {
  const n = emptyNeeds(base.host, base.emailDomain);
  const header = HEADER_RECOMMENDATIONS[f.id];
  if (header) {
    n.headers.push(header);
    return n;
  }
  switch (f.id) {
    case "http-redirect":
      n.httpsRedirect = true;
      return n;
    case "server-header":
      n.hideServerVersion = true;
      return n;
    case "powered-by":
      n.removeHeaders = leakedHeaderNames(f);
      return n;
    case "cookie-secure":
      n.cookieFlags.secure = true;
      return n;
    case "cookie-httponly":
      n.cookieFlags.httpOnly = true;
      return n;
    case "cookie-samesite":
      n.cookieFlags.sameSite = true;
      return n;
    case "tls-protocols":
      // Only when old versions are actually accepted, not when support was merely unknown.
      if (!/^Still accepts TLS 1\./.test(f.summary)) return null;
      n.modernTls = true;
      return n;
    case "security-txt":
      n.securityTxt = securityTxtContent(base.host, base.emailDomain, now);
      return n;
    case "https-available":
    case "tls-valid":
      n.certificate = "missing";
      return n;
    case "tls-expiry":
      n.certificate = "renew";
      return n;
    case "tls-key":
    case "tls-signature":
      n.certificate = "rekey";
      return n;
    default:
      return null;
  }
}

/* ------------------------------------------------------------------ */
/* Platform renderers                                                  */
/* ------------------------------------------------------------------ */

function bareHost(host: string) {
  return host.startsWith("www.") ? host.slice(4) : host;
}

function cookieFlagList(n: Needs) {
  return [
    n.cookieFlags.secure && "Secure",
    n.cookieFlags.httpOnly && "HttpOnly",
    n.cookieFlags.sameSite && "SameSite=Lax",
  ].filter(Boolean) as string[];
}

const HTTPONLY_CAUTION =
  "Only add HttpOnly if no page scripts need to read these cookies (session and login cookies should always be HttpOnly).";

function certbotCommand(n: Needs, plugin: "nginx" | "apache"): string {
  const domains = `-d ${bareHost(n.host)} -d www.${bareHost(n.host)}`;
  if (n.certificate === "renew")
    return "sudo certbot renew\n# Check automatic renewal is scheduled:\nsystemctl list-timers | grep certbot";
  if (n.certificate === "rekey") return `sudo certbot --${plugin} ${domains} --key-type ecdsa --force-renewal`;
  return `sudo certbot --${plugin} ${domains}`;
}

const MANAGED_CERT_NOTE: Record<"vercel" | "netlify" | "cloudflare" | "nextjs", string> = {
  vercel:
    'Vercel issues and renews certificates automatically. If the certificate is wrong, open Project → Settings → Domains and fix any "Invalid Configuration" warning (usually a DNS record pointing elsewhere).',
  netlify:
    'Netlify issues and renews Let\'s Encrypt certificates automatically. Check Domain management → HTTPS and click "Verify DNS configuration" / "Renew certificate".',
  cloudflare:
    'Cloudflare issues edge certificates automatically (SSL/TLS → Edge Certificates). Set SSL/TLS encryption mode to "Full (strict)" and make sure your origin server also has a valid certificate.',
  nextjs:
    "Next.js doesn't handle certificates; your host or reverse proxy does. On Vercel this is automatic; when self-hosting, put nginx/Caddy in front and use Let's Encrypt.",
};

function renderNginx(n: Needs): PlatformFix {
  const blocks: string[] = [];
  const notes: string[] = [];
  const host = n.host;

  if (
    n.headers.length ||
    n.removeHeaders.length ||
    n.cookieFlags.secure ||
    n.cookieFlags.httpOnly ||
    n.cookieFlags.sameSite ||
    n.modernTls ||
    n.securityTxt
  ) {
    const lines: string[] = [`# Inside the server { } block that serves https://${host} (listen 443 ssl).`];
    if (n.headers.length) {
      lines.push(
        "# Note: a location { } block with its own add_header lines stops inheriting these; repeat them there.",
        ...n.headers.map((h) => `add_header ${h.name} "${h.value}" always;`),
      );
    }
    if (n.removeHeaders.length) {
      lines.push(
        "",
        "# Strip technology headers added by the backend (proxy_pass / PHP-FPM):",
        ...n.removeHeaders.flatMap((h) => [`proxy_hide_header ${h};`, `fastcgi_hide_header ${h};`]),
      );
    }
    const flags = cookieFlagList(n);
    if (flags.length) {
      const nginxFlags = flags.map((f) => f.toLowerCase());
      lines.push(
        "",
        "# Add missing flags to cookies set by a proxied backend (nginx 1.19.3+).",
        ...(n.cookieFlags.httpOnly ? [`# ${HTTPONLY_CAUTION}`] : []),
        `proxy_cookie_flags ~ ${nginxFlags.join(" ")};`,
      );
      notes.push(
        "proxy_cookie_flags only affects responses from proxy_pass. For PHP-FPM set session.cookie_secure, session.cookie_httponly and session.cookie_samesite in php.ini instead.",
      );
    }
    if (n.modernTls) {
      lines.push("", "# Only allow modern TLS versions:", "ssl_protocols TLSv1.2 TLSv1.3;");
    }
    if (n.securityTxt) {
      lines.push(
        "",
        "# Serve security.txt (save the file below as /var/www/security.txt):",
        "location = /.well-known/security.txt {",
        "    alias /var/www/security.txt;",
        "    default_type text/plain;",
        "}",
      );
    }
    blocks.push(lines.join("\n"));
  }
  if (n.hideServerVersion) {
    blocks.push(["# In the http { } block of nginx.conf: hide the nginx version.", "server_tokens off;"].join("\n"));
  }
  if (n.httpsRedirect) {
    blocks.push(
      [
        "# Redirect all plain-HTTP requests to HTTPS (a separate server block):",
        "server {",
        "    listen 80;",
        "    listen [::]:80;",
        `    server_name ${bareHost(host)} www.${bareHost(host)};`,
        "    return 301 https://$host$request_uri;",
        "}",
      ].join("\n"),
    );
  }
  const snippets: Snippet[] = blocks.length
    ? [
        {
          filename: "nginx.conf",
          language: "nginx",
          code: `${blocks.join("\n\n")}\n\n# Then test and reload: sudo nginx -t && sudo systemctl reload nginx`,
        },
      ]
    : [];
  if (n.securityTxt) snippets.push({ filename: "/var/www/security.txt", language: "text", code: n.securityTxt });
  if (n.certificate) snippets.push({ filename: "Terminal", language: "text", code: certbotCommand(n, "nginx") });
  return { snippets, notes };
}

function renderApache(n: Needs): PlatformFix {
  const htaccess: string[] = [];
  const serverConf: string[] = [];
  const notes: string[] = [];
  if (n.httpsRedirect) {
    htaccess.push(
      [
        "# Redirect HTTP to HTTPS",
        "<IfModule mod_rewrite.c>",
        "  RewriteEngine On",
        "  RewriteCond %{HTTPS} off",
        "  RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
        "</IfModule>",
      ].join("\n"),
    );
    notes.push(
      "Behind a load balancer or CDN, use `RewriteCond %{HTTP:X-Forwarded-Proto} !https` instead of `%{HTTPS} off`.",
    );
  }
  const flags = cookieFlagList(n);
  if (n.headers.length || n.removeHeaders.length || flags.length) {
    const lines = ["<IfModule mod_headers.c>"];
    lines.push(...n.headers.map((h) => `  Header always set ${h.name} "${h.value}"`));
    for (const h of n.removeHeaders) lines.push(`  Header always unset ${h}`, `  Header unset ${h}`);
    if (flags.length) {
      lines.push("  # Add missing cookie flags (cookies that already have the flag are left alone)");
      if (n.cookieFlags.httpOnly) lines.push(`  # ${HTTPONLY_CAUTION}`);
      const edits: Array<[string, string]> = [];
      if (n.cookieFlags.secure) edits.push(["secure", "Secure"]);
      if (n.cookieFlags.httpOnly) edits.push(["httponly", "HttpOnly"]);
      if (n.cookieFlags.sameSite) edits.push(["samesite", "SameSite=Lax"]);
      for (const [match, flag] of edits) {
        const re = `"(?i)^((?!.*;\\s*${match}).*)$" "$1; ${flag}"`;
        lines.push(`  Header always edit Set-Cookie ${re}`, `  Header edit Set-Cookie ${re}`);
      }
    }
    lines.push("</IfModule>");
    htaccess.push(lines.join("\n"));
  }
  if (n.securityTxt) {
    notes.push("Save the security.txt file below as `.well-known/security.txt` inside your site's document root.");
  }
  if (n.hideServerVersion)
    serverConf.push("# Hide the Apache version and OS", "ServerTokens Prod", "ServerSignature Off");
  if (n.modernTls)
    serverConf.push("# Only allow modern TLS versions (in the SSL virtual host)", "SSLProtocol -all +TLSv1.2 +TLSv1.3");

  const snippets: Snippet[] = [];
  if (htaccess.length) {
    snippets.push({
      filename: ".htaccess",
      language: "apache",
      code: `# ${n.host}: put this in the .htaccess file in your site's root folder.\n\n${htaccess.join("\n\n")}`,
    });
  }
  if (serverConf.length) {
    snippets.push({
      filename: "apache2.conf / httpd.conf",
      language: "apache",
      code: `# These directives are not allowed in .htaccess; add them to the main server config.\n${serverConf.join("\n")}\n\n# Then: sudo apachectl configtest && sudo systemctl reload apache2`,
    });
  }
  if (n.securityTxt) snippets.push({ filename: ".well-known/security.txt", language: "text", code: n.securityTxt });
  if (n.certificate) snippets.push({ filename: "Terminal", language: "text", code: certbotCommand(n, "apache") });
  return { snippets, notes };
}

function appCookieNote(n: Needs): string | null {
  const flags = cookieFlagList(n);
  if (!flags.length) return null;
  const opts = [
    n.cookieFlags.secure && "secure: true",
    n.cookieFlags.httpOnly && "httpOnly: true",
    n.cookieFlags.sameSite && 'sameSite: "lax"',
  ].filter(Boolean);
  return `Cookie flags are set by your application code, not the hosting config: add ${flags.join(", ")} where cookies are created (e.g. Express \`res.cookie(name, value, { ${opts.join(", ")} })\`).${n.cookieFlags.httpOnly ? ` ${HTTPONLY_CAUTION}` : ""}`;
}

function removeHeadersNote(n: Needs, platform: string): string | null {
  if (!n.removeHeaders.length) return null;
  return `${platform} can't strip ${n.removeHeaders.join(", ")} from your app's responses; turn it off in the framework instead (Express: \`app.disable("x-powered-by")\`, Next.js: \`poweredByHeader: false\`, PHP: \`expose_php = Off\`).`;
}

function renderVercel(n: Needs): PlatformFix {
  const snippets: Snippet[] = [];
  const notes: string[] = [];
  if (n.headers.length) {
    const config = { headers: [{ source: "/(.*)", headers: n.headers.map((h) => ({ key: h.name, value: h.value })) }] };
    snippets.push({ filename: "vercel.json", language: "json", code: JSON.stringify(config, null, 2) });
    notes.push('If vercel.json already exists, merge the "headers" entry into it.');
  }
  if (n.httpsRedirect)
    notes.push(
      "Vercel redirects HTTP to HTTPS automatically for every domain; if it isn't happening, the domain is probably served through another proxy or CDN.",
    );
  if (n.hideServerVersion)
    notes.push(
      "Vercel's own Server header has no version; a versioned Server header means something else (a proxy or your app) is setting it.",
    );
  const rm = removeHeadersNote(n, "vercel.json");
  if (rm) notes.push(rm);
  const cookie = appCookieNote(n);
  if (cookie) notes.push(cookie);
  if (n.modernTls)
    notes.push(
      "Vercel only accepts TLS 1.2+; if older versions are accepted, another proxy/CDN in front of the site is terminating TLS. Change its minimum TLS version.",
    );
  if (n.securityTxt)
    snippets.push({ filename: "public/.well-known/security.txt", language: "text", code: n.securityTxt });
  if (n.certificate) notes.push(MANAGED_CERT_NOTE.vercel);
  return { snippets, notes };
}

function renderNetlify(n: Needs): PlatformFix {
  const snippets: Snippet[] = [];
  const notes: string[] = [];
  if (n.headers.length) {
    snippets.push({
      filename: "_headers",
      language: "text",
      code: ["/*", ...n.headers.map((h) => `  ${h.name}: ${h.value}`)].join("\n"),
    });
    notes.push(
      "Put _headers in your publish directory (e.g. public/ or dist/). Netlify's netlify.toml [[headers]] works too.",
    );
  }
  if (n.httpsRedirect)
    notes.push(
      "Netlify redirects HTTP to HTTPS automatically once a certificate is provisioned (Domain management → HTTPS).",
    );
  if (n.hideServerVersion)
    notes.push(
      "Netlify's Server header has no version; a versioned one comes from a proxy or function in front of it.",
    );
  const rm = removeHeadersNote(n, "_headers");
  if (rm) notes.push(rm);
  const cookie = appCookieNote(n);
  if (cookie) notes.push(cookie);
  if (n.modernTls)
    notes.push(
      "Netlify only accepts TLS 1.2+; if older versions are accepted, a proxy/CDN in front of the site is terminating TLS.",
    );
  if (n.securityTxt)
    snippets.push({ filename: "<publish dir>/.well-known/security.txt", language: "text", code: n.securityTxt });
  if (n.certificate) notes.push(MANAGED_CERT_NOTE.netlify);
  return { snippets, notes };
}

function renderCloudflare(n: Needs): PlatformFix {
  const steps: string[] = [];
  const notes: string[] = [];
  if (n.headers.length || n.removeHeaders.length) {
    steps.push(
      `Cloudflare dashboard → ${bareHost(n.host)} → Rules → Transform Rules → Modify Response Header → Create rule`,
      "  Rule name: Security headers",
      "  If incoming requests match: All incoming requests",
      "  Then:",
      ...n.headers.map((h) => `    Set static   ${h.name}   =   ${h.value}`),
      ...n.removeHeaders.map((h) => `    Remove       ${h}`),
      "  → Deploy",
    );
    if (n.headers.some((h) => h.name === "Strict-Transport-Security")) {
      notes.push("For HSTS you can instead use SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS).");
    }
  }
  if (n.httpsRedirect) steps.push("", "SSL/TLS → Edge Certificates → Always Use HTTPS → On");
  if (n.modernTls) steps.push("", "SSL/TLS → Edge Certificates → Minimum TLS Version → TLS 1.2");
  if (n.securityTxt)
    steps.push("", "Security Center → Security.txt → Add (paste the fields below), or serve the file from your origin");
  if (n.hideServerVersion)
    notes.push(
      'Cloudflare replaces the Server header with "cloudflare" for proxied (orange-cloud) records. Make sure the record is proxied, or hide the version on the origin server.',
    );
  const cookie = appCookieNote(n);
  if (cookie) notes.push(cookie);
  if (n.certificate) notes.push(MANAGED_CERT_NOTE.cloudflare);
  const snippets: Snippet[] = steps.length
    ? [{ filename: "Cloudflare dashboard", language: "text", code: steps.join("\n") }]
    : [];
  if (n.securityTxt) snippets.push({ filename: "security.txt", language: "text", code: n.securityTxt });
  return { snippets, notes };
}

function renderNext(n: Needs): PlatformFix {
  const snippets: Snippet[] = [];
  const notes: string[] = [];
  const removesPoweredBy = n.removeHeaders.includes("X-Powered-By");
  if (n.headers.length || removesPoweredBy) {
    const lines = ['import type { NextConfig } from "next";', ""];
    if (n.headers.length) {
      lines.push(
        "const securityHeaders = [",
        ...n.headers.map((h) => `  { key: ${JSON.stringify(h.name)}, value: ${JSON.stringify(h.value)} },`),
        "];",
        "",
      );
    }
    lines.push("const nextConfig: NextConfig = {");
    if (removesPoweredBy) lines.push("  poweredByHeader: false,");
    if (n.headers.length) {
      lines.push("  async headers() {", '    return [{ source: "/:path*", headers: securityHeaders }];', "  },");
    }
    lines.push("};", "", "export default nextConfig;");
    snippets.push({ filename: "next.config.ts", language: "ts", code: lines.join("\n") });
    notes.push("Merge these into your existing next.config if you already have one.");
  }
  const flags = cookieFlagList(n);
  if (flags.length) {
    const opts = [
      n.cookieFlags.httpOnly && "  httpOnly: true,",
      n.cookieFlags.secure && "  secure: true,",
      n.cookieFlags.sameSite && '  sameSite: "lax",',
    ].filter(Boolean);
    snippets.push({
      filename: "Where you set cookies (Route Handler / Server Action)",
      language: "ts",
      code: [
        'import { cookies } from "next/headers";',
        "",
        "(await cookies()).set(name, value, {",
        ...(opts as string[]),
        '  path: "/",',
        "});",
      ].join("\n"),
    });
    if (n.cookieFlags.httpOnly) notes.push(HTTPONLY_CAUTION);
  }
  if (n.httpsRedirect)
    notes.push(
      "Next.js doesn't handle HTTP→HTTPS redirects; your host does. Vercel does it automatically; when self-hosting, redirect in nginx/Caddy.",
    );
  if (n.hideServerVersion)
    notes.push("Next.js doesn't send a versioned Server header; it's coming from the server or proxy in front of it.");
  if (n.modernTls) notes.push("TLS versions are configured on your host or reverse proxy, not in Next.js.");
  if (n.securityTxt)
    snippets.push({ filename: "public/.well-known/security.txt", language: "text", code: n.securityTxt });
  if (n.certificate) notes.push(MANAGED_CERT_NOTE.nextjs);
  return { snippets, notes };
}

const RENDERERS: Record<Platform, (n: Needs) => PlatformFix> = {
  nginx: renderNginx,
  apache: renderApache,
  vercel: renderVercel,
  netlify: renderNetlify,
  cloudflare: renderCloudflare,
  nextjs: renderNext,
};

function renderAll(n: Needs): Record<Platform, PlatformFix> {
  return Object.fromEntries(PLATFORMS.map((p) => [p.id, RENDERERS[p.id](n)])) as Record<Platform, PlatformFix>;
}

/* ------------------------------------------------------------------ */
/* DNS fixes                                                           */
/* ------------------------------------------------------------------ */

const CA_DOMAINS: Array<[RegExp, string]> = [
  [/let'?s encrypt/i, "letsencrypt.org"],
  [/digicert|thawte|geotrust|rapidssl/i, "digicert.com"],
  [/sectigo|comodo|usertrust|zerossl/i, "sectigo.com"],
  [/google trust|^gts\b/i, "pki.goog"],
  [/amazon/i, "amazon.com"],
  [/globalsign/i, "globalsign.com"],
  [/godaddy|starfield/i, "godaddy.com"],
  [/entrust/i, "entrust.net"],
  [/ssl\.com/i, "ssl.com"],
  [/microsoft/i, "microsoft.com"],
  [/buypass/i, "buypass.com"],
];

export function caaIssuerFor(issuerOrg: string | null): string | null {
  if (!issuerOrg) return null;
  return CA_DOMAINS.find(([re]) => re.test(issuerOrg))?.[1] ?? null;
}

const quoteTxt = (s: string) => `"${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;

export function fixedSpf(record: string | null): string | null {
  if (!record) return null;
  if (/(^|\s)redirect=/i.test(record)) return null;
  if (/(^|\s)[+?~-]?all(\s|$)/i.test(record)) return record.replace(/(^|\s)[+?~-]?all(?=\s|$)/i, "$1-all");
  return `${record} -all`;
}

function dnsFixes(report: ScanReport, findings: Map<string, Finding>): Array<{ id: string; fix: FindingFix }> {
  const domain = report.details.email.domain;
  const out: Array<{ id: string; fix: FindingFix }> = [];

  const spf = findings.get("spf");
  if (needsAttention(spf)) {
    const fixed = fixedSpf(report.details.email.spfRecord);
    const code = fixed
      ? `; Replace your current SPF record with:\n${domain}.  TXT  ${quoteTxt(fixed)}`
      : [
          "; List the services that send email for you, then end with -all:",
          `${domain}.  TXT  ${quoteTxt("v=spf1 include:_spf.your-email-provider.example -all")}`,
          "",
          "; If this domain never sends email, use this instead:",
          `${domain}.  TXT  ${quoteTxt("v=spf1 -all")}`,
        ].join("\n");
    out.push({
      id: "spf",
      fix: {
        kind: "generic",
        snippets: [{ filename: "DNS record", language: "dns", code }],
        notes: [
          "Keep exactly one TXT record starting with v=spf1. Your email provider's help pages list the include: value to use (e.g. Google Workspace: include:_spf.google.com, Microsoft 365: include:spf.protection.outlook.com).",
        ],
      },
    });
  }

  const dmarc = findings.get("dmarc");
  if (needsAttention(dmarc)) {
    const current = dmarc!.evidence?.split(": ").slice(1).join(": ");
    let record = `v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${domain}`;
    if (current && /p=none/i.test(current))
      record = current.replace(/p=none/i, "p=quarantine").replace(/;\s*pct=\d+/i, "");
    else if (current && /pct=\d+/i.test(current)) record = current.replace(/;\s*pct=\d+/i, "");
    out.push({
      id: "dmarc",
      fix: {
        kind: "generic",
        snippets: [{ filename: "DNS record", language: "dns", code: `_dmarc.${domain}.  TXT  ${quoteTxt(record)}` }],
        notes: [
          "Not sure all your legitimate email passes SPF/DKIM yet? Start with p=none for 2–4 weeks, read the reports sent to the rua address, then move to quarantine and finally p=reject.",
        ],
      },
    });
  }

  const caa = findings.get("caa");
  if (needsAttention(caa)) {
    const ca = caaIssuerFor(report.details.tls?.issuerOrg ?? null);
    const lines = [
      ca
        ? `; Your current certificate is from ${report.details.tls?.issuerOrg}, so allow ${ca}:`
        : "; Replace letsencrypt.org with the certificate authority you use:",
      `${domain}.  CAA  0 issue ${quoteTxt(ca ?? "letsencrypt.org")}`,
      "; Where CAs should report suspicious requests:",
      `${domain}.  CAA  0 iodef ${quoteTxt(`mailto:security@${domain}`)}`,
    ];
    out.push({
      id: "caa",
      fix: {
        kind: "generic",
        snippets: [{ filename: "DNS record", language: "dns", code: lines.join("\n") }],
        notes: [
          "List every CA you use (your host's managed certificates too) or renewals will fail. Cloudflare adds the CAs it needs automatically when you create a CAA record there.",
        ],
      },
    });
  }

  const dnssec = findings.get("dnssec");
  if (needsAttention(dnssec)) {
    out.push({
      id: "dnssec",
      fix: {
        kind: "generic",
        snippets: [
          {
            filename: "Steps",
            language: "text",
            code: [
              "1. At your DNS provider, enable DNSSEC signing for the zone",
              "   (Cloudflare: DNS → Settings → Enable DNSSEC; Route 53: Hosted zone → DNSSEC signing).",
              "2. Copy the DS record it shows (key tag, algorithm, digest type, digest).",
              '3. At your domain registrar, add that DS record (often under "DNSSEC").',
              "   If your registrar is also your DNS provider, this is usually one click.",
              "4. Wait for it to propagate, then scan again.",
            ].join("\n"),
          },
        ],
        notes: [
          "Do the registrar step last: publishing a DS record before the zone is signed makes the domain stop resolving.",
        ],
      },
    });
  }
  return out;
}

/* ------------------------------------------------------------------ */

export function buildFixes(report: ScanReport, now = new Date()): FixBundle {
  const host = report.domain;
  const base = emptyNeeds(host, report.details.email.domain);
  const findings = new Map(report.categories.flatMap((c) => c.findings).map((f) => [f.id, f]));
  const byFinding: Record<string, FindingFix> = {};
  let combinedNeeds = base;

  for (const f of findings.values()) {
    if (!needsAttention(f)) continue;
    const needs = needsForFinding(f, base, now);
    if (!needs || !hasNeeds(needs)) continue;
    combinedNeeds = mergeNeeds(combinedNeeds, needs);
    byFinding[f.id] = {
      kind: "platform",
      warning: f.id === "csp" ? CSP_WARNING : undefined,
      byPlatform: renderAll(needs),
    };
  }

  const dns = dnsFixes(report, findings);
  for (const d of dns) byFinding[d.id] = d.fix;
  const dnsSnippets = dns.flatMap((d) =>
    d.fix.kind === "generic" ? d.fix.snippets.filter((s) => s.language === "dns") : [],
  );
  const dnsSteps = dns.flatMap((d) =>
    d.fix.kind === "generic" ? d.fix.snippets.filter((s) => s.language !== "dns") : [],
  );

  return {
    byFinding,
    combined: renderAll(combinedNeeds),
    dns: {
      snippets: [
        ...(dnsSnippets.length
          ? [{ filename: "DNS records", language: "dns" as const, code: dnsSnippets.map((s) => s.code).join("\n\n") }]
          : []),
        ...dnsSteps,
      ],
      notes: dns.flatMap((d) => (d.fix.kind === "generic" ? d.fix.notes : [])),
    },
    combinedWarning: combinedNeeds.headers.some((h) => h.name === "Content-Security-Policy") ? CSP_WARNING : undefined,
    hasAny: Object.keys(byFinding).length > 0,
  };
}
