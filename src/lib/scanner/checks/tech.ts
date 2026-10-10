import type { Hop } from "../net";
import type { Technology } from "../types";
import { header } from "../util";
import { parseSetCookie } from "./cookies";

const VERSION = /\bv?(\d+(?:\.\d+)+)/i;

interface HeaderRule {
  header: string;
  match: RegExp;
  name: string;
  category: string;
  /** Capture the version from the header value when present. */
  version?: boolean;
}

const HEADER_RULES: HeaderRule[] = [
  { header: "server", match: /\bnginx\b/i, name: "nginx", category: "Web server", version: true },
  { header: "server", match: /\bopenresty\b/i, name: "OpenResty", category: "Web server", version: true },
  { header: "server", match: /\bapache\b/i, name: "Apache", category: "Web server", version: true },
  { header: "server", match: /microsoft-iis/i, name: "Microsoft IIS", category: "Web server", version: true },
  { header: "server", match: /litespeed/i, name: "LiteSpeed", category: "Web server", version: true },
  { header: "server", match: /\bcaddy\b/i, name: "Caddy", category: "Web server", version: true },
  { header: "server", match: /\bkestrel\b/i, name: "Kestrel (ASP.NET Core)", category: "Web server" },
  { header: "server", match: /\bgunicorn\b/i, name: "Gunicorn", category: "Web server", version: true },
  { header: "server", match: /\bcloudflare\b/i, name: "Cloudflare", category: "CDN" },
  { header: "server", match: /akamaighost/i, name: "Akamai", category: "CDN" },
  { header: "server", match: /\bvercel\b/i, name: "Vercel", category: "Hosting" },
  { header: "server", match: /\bnetlify\b/i, name: "Netlify", category: "Hosting" },
  { header: "server", match: /amazons3/i, name: "Amazon S3", category: "Hosting" },
  { header: "server", match: /^github\.com$/i, name: "GitHub", category: "Hosting" },
  { header: "server", match: /^gws$|^gfe/i, name: "Google Web Server", category: "Web server" },
  { header: "server", match: /squarespace/i, name: "Squarespace", category: "Website builder" },
  { header: "server", match: /^wix/i, name: "Wix", category: "Website builder" },
  { header: "x-powered-by", match: /\bphp\b/i, name: "PHP", category: "Language", version: true },
  { header: "x-powered-by", match: /asp\.net/i, name: "ASP.NET", category: "Framework" },
  { header: "x-powered-by", match: /\bexpress\b/i, name: "Express", category: "Framework" },
  { header: "x-powered-by", match: /next\.js/i, name: "Next.js", category: "Framework", version: true },
  { header: "x-powered-by", match: /\bnuxt/i, name: "Nuxt", category: "Framework" },
  { header: "x-powered-by", match: /wp engine/i, name: "WP Engine", category: "Hosting" },
  { header: "x-powered-by", match: /\bplesk/i, name: "Plesk", category: "Hosting panel" },
  {
    header: "x-powered-by",
    match: /phusion passenger/i,
    name: "Phusion Passenger",
    category: "App server",
    version: true,
  },
  { header: "x-aspnet-version", match: /./, name: "ASP.NET", category: "Framework", version: true },
  { header: "x-aspnetmvc-version", match: /./, name: "ASP.NET MVC", category: "Framework", version: true },
  { header: "x-generator", match: /drupal/i, name: "Drupal", category: "CMS", version: true },
  { header: "x-generator", match: /wordpress/i, name: "WordPress", category: "CMS", version: true },
  { header: "x-drupal-cache", match: /./, name: "Drupal", category: "CMS" },
  { header: "x-drupal-dynamic-cache", match: /./, name: "Drupal", category: "CMS" },
  { header: "x-pingback", match: /xmlrpc\.php/i, name: "WordPress", category: "CMS" },
  { header: "link", match: /rel="https:\/\/api\.w\.org\/"/i, name: "WordPress", category: "CMS" },
  { header: "x-shopify-stage", match: /./, name: "Shopify", category: "E-commerce" },
  { header: "x-shopid", match: /./, name: "Shopify", category: "E-commerce" },
  { header: "powered-by", match: /shopify/i, name: "Shopify", category: "E-commerce" },
  { header: "x-wix-request-id", match: /./, name: "Wix", category: "Website builder" },
  { header: "cf-ray", match: /./, name: "Cloudflare", category: "CDN" },
  { header: "x-vercel-id", match: /./, name: "Vercel", category: "Hosting" },
  { header: "x-nf-request-id", match: /./, name: "Netlify", category: "Hosting" },
  { header: "x-amz-cf-id", match: /./, name: "Amazon CloudFront", category: "CDN" },
  { header: "x-fastly-request-id", match: /./, name: "Fastly", category: "CDN" },
  { header: "x-github-request-id", match: /./, name: "GitHub", category: "Hosting" },
  { header: "x-varnish", match: /./, name: "Varnish", category: "Cache" },
];

const COOKIE_RULES: Array<{ match: RegExp; name: string; category: string }> = [
  { match: /^PHPSESSID$/i, name: "PHP", category: "Language" },
  { match: /^ASP\.NET_SessionId$|^\.AspNetCore\.|^\.ASPXAUTH$/i, name: "ASP.NET", category: "Framework" },
  { match: /^JSESSIONID$/i, name: "Java (servlet)", category: "Language" },
  { match: /^wordpress_|^wp-settings-|^wp_woocommerce/i, name: "WordPress", category: "CMS" },
  { match: /^laravel_session$/i, name: "Laravel", category: "Framework" },
  { match: /^csrftoken$|^django_language$/i, name: "Django", category: "Framework" },
  { match: /^_shopify_|^cart_sig$|^secure_customer_sig$/i, name: "Shopify", category: "E-commerce" },
  { match: /^__cf_bm$|^cf_clearance$|^__cflb$/i, name: "Cloudflare", category: "CDN" },
  { match: /^connect\.sid$/i, name: "Express", category: "Framework" },
  { match: /^ci_session$/i, name: "CodeIgniter", category: "Framework" },
  { match: /^PrestaShop-/i, name: "PrestaShop", category: "E-commerce" },
  { match: /^mage-cache-|^form_key$/i, name: "Magento", category: "E-commerce" },
  { match: /^SSESS[0-9a-f]+$|^SESS[0-9a-f]{32}$/i, name: "Drupal", category: "CMS" },
  { match: /^AWSALB|^AWSELB/i, name: "AWS load balancer", category: "Hosting" },
];

/**
 * Passive fingerprinting from response headers and cookie NAMES only (values are
 * never looked at). Nothing extra is requested.
 */
export function detectTechnologies(hops: Hop[]): Technology[] {
  const final = hops.at(-1);
  if (!final) return [];
  const found = new Map<string, Technology>();
  const add = (t: Technology) => {
    const existing = found.get(t.name);
    // Keep the first detection, but upgrade it if a later rule exposes a version.
    if (!existing || (!existing.version && t.version)) found.set(t.name, t);
  };

  for (const rule of HEADER_RULES) {
    const value = header(final.headers, rule.header);
    if (!value || !rule.match.test(value)) continue;
    let version: string | null = null;
    if (rule.version) {
      // The version sits in the product's own token ("nginx/1.18.0") or the next one ("Drupal 10.1").
      const tokens = value.split(/\s+/);
      const at = tokens.findIndex((t) => rule.match.test(t));
      const next = tokens[at + 1] ?? "";
      const candidates = at >= 0 ? [tokens[at], /^v?\d/i.test(next) ? next : ""] : [value];
      version = candidates.map((c) => c.match(VERSION)?.[1]).find(Boolean) ?? null;
    }
    add({ name: rule.name, category: rule.category, version, source: `${rule.header} header` });
  }

  for (const hop of hops) {
    for (const line of hop.headers["set-cookie"] ?? []) {
      const cookie = parseSetCookie(line);
      if (!cookie) continue;
      const rule = COOKIE_RULES.find((r) => r.match.test(cookie.name));
      if (rule) add({ name: rule.name, category: rule.category, version: null, source: `cookie ${cookie.name}` });
    }
  }
  return [...found.values()];
}
