# SiteGrade: Website Security Scanner

Enter a domain, get an **A+ to F security grade** with a clear report, plain-English explanations and
**copy-paste fixes** for nginx, Apache, Vercel, Netlify, Cloudflare and Next.js.

Everything is **passive**: the scanner only does what a browser or mail server would do (load the homepage, do a TLS
handshake, read public files and DNS records). No port scanning, no vulnerability probing, no brute forcing. The
**Hacker's View** adds what anyone can learn from free public data sources (no API keys needed), without touching the
target.

## What it checks

| Area | Points | Checks (points) |
| --- | ---: | --- |
| **HTTPS** | 12 | Loads over HTTPS (8) · HTTP redirects to HTTPS (4) |
| **TLS certificate & protocols** | 22 | Trusted & matches the domain (10) · not expiring within 30 days (4) · TLS 1.0/1.1 refused, 1.2/1.3 supported (5) · key strength (2) · no SHA-1/MD5 signatures (1). Also shows cipher, key exchange, certificate chain and the names on the certificate |
| **Security headers** | 32 | HSTS (7) · Content-Security-Policy (9) · X-Frame-Options / frame-ancestors (5) · X-Content-Type-Options (5) · Referrer-Policy (3) · Permissions-Policy (3) |
| **Cookies** | 8 | `Secure` (4) · `HttpOnly` (2) · `SameSite` (2) on cookies set by the homepage |
| **Information leakage** | 5 | Version in `Server` (3) · `X-Powered-By` & similar (2) · technology fingerprint from headers and cookie *names* (info) |
| **Email security** | 12 | SPF (5) · DMARC policy none/quarantine/reject (7) |
| **DNS security** | 6 | CAA record (3) · DNSSEC (3) |
| **Public files** | 3 | `/.well-known/security.txt` with Contact + unexpired Expires (3) · robots.txt Disallow paths, sensitive-looking ones highlighted (info, never requested) |

**Grading:** pass = full points, warning = partial, fail = 0; informational findings never affect the score. The total
out of 100 maps to **A+ ≥ 95** (and no failed checks), **A ≥ 85**, **B ≥ 70**, **C ≥ 55**, **D ≥ 40**, **F < 40**.
Critical problems cap the grade: no HTTPS → **F**; untrusted or expired certificate → **D**; weak key → **C**;
a database exposed to the internet (per Shodan) → **C**; TLS 1.0/1.1 accepted → **B**.

**Exposure penalties** (from Shodan's public data, max −15 in total): −5 per exposed database port, −3 per exposed
remote-admin port (ports capped at −12), −3 for known CVEs (−6 for 5 or more). No data means no penalty. Breaches are
never graded. The weights live in `src/lib/scanner/weights.ts` (rendered on the About page) and a test
keeps them in sync with the checks.

## Features

- **Fix generator.** Every failed or warning check gets a "How to fix" panel with tabs for nginx, Apache (.htaccess),
  Vercel (vercel.json), Netlify (_headers), Cloudflare (dashboard steps) and Next.js (next.config). Snippets contain
  only what's missing (e.g. just the absent headers); DNS fixes are tailored (your SPF record rewritten to `-all`, CAA
  for the CA that issued your current certificate). An **All fixes** view merges everything per platform. The starter
  CSP comes with a "test it as Report-Only first" warning.
- **Clickjacking demo.** Shown only when the site has no X-Frame-Options or CSP frame-ancestors: the real site in a
  `sandbox=""` iframe with a non-functional "Click here to win!" overlay and an attacker/victim view toggle. Falls back
  to an illustration if the site can't be shown.
- **Deep TLS check.** One handshake per protocol version (TLS 1.0–1.3), cipher, key type/size, signature algorithm,
  chain and SAN list.
- **Hacker's View.** One card per public source, streamed in as each one answers:
  - *Exposed services* — open ports (labelled; databases and remote-admin flagged high risk), known CVEs linked to
    NVD, software (CPEs) and tags from **Shodan InternetDB** for up to two of the site's IPs. Labelled "Data from
    Shodan's existing public scans. We did not scan this server."
  - *Past data breaches* — name, date, accounts, leaked data types and verified status from **Have I Been Pwned**
    (descriptions stripped of HTML). Context only.
  - *Domain age* — registration/expiry/update dates and registrar via **RDAP** (rdap.org → the registry), with
    warnings for domains younger than 30 days or expiring within 30 days.
  - *Site history* — first and latest **Wayback Machine** snapshot and approximate snapshot count, with a link to the
    oldest snapshot.
  - *Server location* — country, city, hosting provider and ASN from **ipwho.is**, on a small **Leaflet** map with
    **OpenStreetMap** tiles.
- **Recent scans.** The last scans are kept in your browser's localStorage (nothing on the server), with "up from C" /
  "down from A" trends for repeat scans.
- Streaming progress, shareable links (`/?domain=example.com`), copy-as-text report, mobile layout.

Built with Next.js (App Router) · TypeScript · Tailwind CSS. No database.

---

## Local setup

Requirements: **Node.js 20.9+** (Node 24 recommended) and npm.

```bash
npm install
cp .env.example .env.local   # optional for local dev
npm run dev                  # http://localhost:3000
```

Other scripts:

```bash
npm run build && npm start   # production build (pages use a per-request CSP nonce)
npm test                     # unit tests (validation, SSRF, checks, TLS probes vs a local server, fixes, history)
npm run test:network         # + live tests (SSRF redirects, body limits, TLS 1.0, every public data source)
npm run lint
npm run typecheck
```

You can also call the API directly. It streams newline-delimited JSON progress events and then the report:

```bash
curl -N -X POST http://localhost:3000/api/scan \
  -H 'content-type: application/json' -d '{"domain":"github.com"}'
```

Shareable result links look like `https://your-domain.com/?domain=github.com`.

### Environment variables

| Variable                    | Default                    | Purpose                                                                 |
| --------------------------- | -------------------------- | ----------------------------------------------------------------------- |
| `NEXT_PUBLIC_SITE_URL`      | Vercel production URL      | Canonical URL for SEO / Open Graph / sitemap. Set it to your custom domain. |
| `RATE_LIMIT_MAX`            | `10`                       | Scans per IP per window                                                 |
| `RATE_LIMIT_WINDOW_SECONDS` | `300`                      | Rate-limit window                                                       |

---

## Deploying to Vercel

1. **Push to GitHub** (or GitLab/Bitbucket):
   ```bash
   git add -A && git commit -m "SiteGrade security scanner"
   git remote add origin https://github.com/<you>/sitegrade.git
   git push -u origin main
   ```
2. Go to **vercel.com → Add New… → Project**, import the repository. Vercel detects Next.js automatically.
   Keep the default build settings.
3. Under **Environment Variables**, add `NEXT_PUBLIC_SITE_URL` = `https://your-domain.com` (your final domain).
4. Click **Deploy**. You'll get a `*.vercel.app` URL in about a minute.

Alternatively, with the CLI: `npm i -g vercel && vercel` (preview) then `vercel --prod`.

> The scan API runs on the Node.js runtime (it uses Node's `tls`, `dns` and `dgram` modules) with
> `maxDuration = 60` seconds. Typical scans take 1–5 seconds. DNSSEC detection sends a UDP DNS query to the
> platform's own resolver (Vercel allows this); if a host blocks it, the check reports "couldn't determine".

### Connecting your custom domain

1. In the Vercel project, open **Settings → Domains** and add `your-domain.com` (Vercel will offer to add
   `www.your-domain.com` too; choose which one redirects to the other).
2. Vercel shows the DNS records to create. At your domain registrar (Namecheap, Cloudflare, GoDaddy, …):
   - **Apex domain** (`your-domain.com`): add the **A record** Vercel shows.
   - **`www` subdomain**: add the **CNAME record** Vercel shows.
   - Or switch your domain's **nameservers** to Vercel's, and Vercel manages DNS for you.
3. Wait for DNS to propagate (minutes to a few hours). Vercel issues the TLS certificate automatically
   and the domain shows **Valid Configuration**.
4. Make sure `NEXT_PUBLIC_SITE_URL` matches the primary domain, then **redeploy** (Deployments → ⋯ → Redeploy)
   so canonical URLs and Open Graph tags use it.
5. Scan your own domain with SiteGrade. The app's own headers should give it a top score for the web
   checks. Email (SPF/DMARC) depends on your domain's DNS. If the domain doesn't send email, add
   `TXT @ "v=spf1 -all"` and `TXT _dmarc "v=DMARC1; p=reject"`.

> **HSTS note:** the app sends `Strict-Transport-Security: max-age=63072000; includeSubDomains`. That tells
> browsers to use HTTPS for **every subdomain** of your domain for two years. If you run any subdomain without
> HTTPS, remove `includeSubDomains` in `next.config.ts`.

---

## How the scanner protects itself

A server that fetches arbitrary URLs is a classic SSRF target, so the scanner is locked down:

- **Passive only.** Requests made per scan: the homepage over HTTPS and HTTP (following redirects), `/.well-known/security.txt`,
  `/robots.txt`, one TLS handshake per protocol version plus one for the certificate, and DNS queries (A/AAAA, TXT,
  CAA, SOA, DS) to the system resolver. Paths listed in robots.txt are displayed, never requested.
- **Strict input validation** (`src/lib/scanner/domain.ts`): input is parsed with the WHATWG URL parser, and
  protocol, path, port and credentials are stripped. Only syntactically valid public hostnames are accepted. IP
  literals in any notation (`127.0.0.1`, `0x7f.1`, `2130706433`, `[::1]`) and reserved names (`localhost`, `.local`,
  `.internal`, `.test`, `.onion`, …) are rejected.
- **SSRF protection on every connection** (`src/lib/scanner/ip.ts`, `net.ts`):
  - The domain is resolved before scanning, and the scan is refused if **any** address is private, loopback,
    link-local, CGNAT, multicast, documentation or otherwise reserved (10/8, 172.16/12, 192.168/16, 127/8,
    169.254/16, 100.64/10, 0/8, 224/4, 240/4, ::1, ::, fc00::/7, fe80::/10, ff00::/8, NAT64, 6to4, IPv4-mapped…).
    IPv6 uses an allow-list: only global unicast `2000::/3` minus special ranges.
  - Every socket (HTTP, HTTPS, the certificate inspection and each TLS version probe) connects through a custom
    `lookup` that repeats this check. The address that is validated is the address that is connected to, so **DNS
    rebinding can't bypass it**. A test proves a probe to `localhost` never reaches a listening local server.
  - Redirects are followed manually and **every hop is re-validated**. Only `http`/`https` on default ports are
    allowed, IP-literal targets are checked explicitly, and URLs with credentials are refused.
- **Limits:** 5-second timeout on every network request (DNS, TCP, TLS, HTTP), at most **5 redirects**, headers
  capped at 64 KB. Response bodies are never read except security.txt (≤ 32 KB) and robots.txt (≤ 64 KB), which must
  be `text/plain`.
- **Legacy TLS is contained:** TLS 1.0/1.1 handshakes need OpenSSL's `@SECLEVEL=0`. That setting exists only inside
  `probeTlsVersion()` for those two versions; those connections send no data, and every other connection uses
  modern defaults (TLS 1.2+).
- **Rate limiting:** a sliding-window limit per client IP (`src/lib/rate-limit.ts`), returning `429` with
  `Retry-After`. It runs in memory, so on Vercel it applies **per serverless instance**. For a strict global limit,
  add a [Vercel WAF rate-limit rule](https://vercel.com/docs/vercel-firewall/vercel-waf/rate-limiting) for
  `/api/scan` or move the limiter to a shared store such as Upstash Redis.
- **No XSS from scanned content:** headers, DNS records and file contents are rendered only as React text nodes
  (never `dangerouslySetInnerHTML`), and control characters are stripped. Cookie *values* are discarded server-side;
  only names and flags are used.
- **Clickjacking demo containment:** the report page's CSP allows `frame-src 'self'` only. It frames `/frame-demo`,
  a tiny route generated per request whose CSP is `default-src 'none'; frame-src <exact scanned origin>;
  frame-ancestors 'self'`. The target URL is re-validated (https, public hostname, default port), escaped, and
  embedded with `sandbox=""` (no scripts, forms, popups or top navigation); the bait overlay is a plain,
  non-interactive `div`. Opened directly (not in a frame), the route refuses to embed anything.
- **The app's own headers:** nonce-based CSP with `'strict-dynamic'` (set per request in `src/proxy.ts`), HSTS,
  `X-Frame-Options: DENY`, `nosniff`, a strict Referrer-Policy, Permissions-Policy, COOP, and `X-Powered-By` removed.
- **Public data sources are untrusted input.** Calls to Shodan, HIBP, RDAP, the Wayback Machine and ipwho.is go
  through the same SSRF-guarded client (safe lookup on every hop, 5s per request, max 5 redirects; RDAP's redirect to
  the registry is re-validated) with **verified** TLS and response-size caps (16–512 KB). Every field is validated
  (CVE/CPE/hostname patterns, port ranges, dates, coordinate ranges), lengths and list sizes are capped, HIBP's HTML
  descriptions are stripped to text, and everything renders as text. Links are built from validated parts (NVD from
  a checked CVE ID, Wayback from a 14-digit timestamp and our own domain) and open with `rel="noopener noreferrer"`.
  Results are cached in memory for 12–24 h (failures for 10 min) and each source has a 12 s ceiling; a source that
  fails, times out or rate-limits just hides its card.
- **Map:** Leaflet is bundled (no third-party script). The CSP's only addition is
  `img-src https://tile.openstreetmap.org` for map tiles. No Leaflet popups/tooltips (they'd render HTML).
- **Privacy note:** the scanned domain and its IP are sent to these services to look them up, and the visitor's
  browser loads map tiles from OpenStreetMap. For heavy traffic, use a commercial tile provider (OSM's tile usage
  policy).
- **Local history only:** recent scans live in `localStorage`, every access wrapped in try/catch and validated on read.

---

## Project structure

```
src/
├── app/
│   ├── api/scan/route.ts      # POST /api/scan: validation, rate limit, SSRF pre-check, NDJSON stream
│   ├── frame-demo/route.ts    # Inner page of the clickjacking demo (per-request CSP for one origin)
│   ├── about/page.tsx         # About page, incl. "How grading works"
│   ├── page.tsx               # Landing page + scanner
│   ├── layout.tsx             # Metadata/SEO, fonts, header/footer
│   ├── opengraph-image.tsx    # Generated social preview image
│   ├── robots.ts, sitemap.ts, icon.svg, not-found.tsx
├── components/
│   ├── scanner.tsx            # Form, streaming client, animated progress, recent scans
│   ├── report.tsx             # Grade badge, breakdown, category cards
│   ├── fix-panel.tsx          # Platform tabs, code blocks, "All fixes"
│   ├── clickjack-demo.tsx     # Sandboxed iframe + fake overlay + illustration fallback
│   ├── details.tsx            # TLS details, technologies, robots.txt paths
│   ├── recent-scans.tsx       # localStorage history list and trend badge
│   ├── hackers-view.tsx       # Hacker's View cards (Shodan, HIBP, RDAP, Wayback, location)
│   ├── server-map.tsx         # Leaflet + OpenStreetMap map (client-only)
│   ├── copy.tsx, ui.tsx, icons.tsx, site-header.tsx, site-footer.tsx
├── lib/
│   ├── scanner/
│   │   ├── index.ts           # runScan(): runs checks in parallel, builds the report
│   │   ├── domain.ts          # input normalisation and validation
│   │   ├── ip.ts              # public/private IP classification
│   │   ├── net.ts             # safe lookup, HTTP(S) with manual redirects, TLS inspection + version probes
│   │   ├── dnsraw.ts          # minimal DNS client for DS/SOA (DNSSEC detection)
│   │   ├── scoring.ts         # score → grade, grade caps
│   │   ├── weights.ts         # documented points per check
│   │   ├── types.ts           # shared types, category weights
│   │   └── checks/            # https, tls, headers, cookies, leakage, tech, email, dns, files
│   ├── intel/                 # Hacker's View: shodan, hibp, rdap, wayback, geo, cache, http, sanitize
│   ├── fixes.ts               # fix generator (per finding and combined, per platform)
│   ├── frame-demo.ts          # demo target validation + HTML/CSP
│   ├── history.ts             # localStorage scan history
│   ├── rate-limit.ts, report-text.ts
│   └── site.ts                # name, URL, SEO text (rename the project here)
└── proxy.ts                   # per-request CSP nonce
tests/                         # vitest unit tests + opt-in live network tests
```

## Example results

Results at the time of writing (live sites change):

| Site | Grade | Why |
| --- | :---: | --- |
| `github.com` | **A** (88) | Strong TLS and headers, CAA, security.txt; −3 because Shodan sees SSH (git) on port 22; no DNSSEC |
| `mozilla.org` | **A** (87) | |
| `cloudflare.com` | **B** (86, capped) | Its edge still accepts TLS 1.0/1.1 (confirmed with `openssl s_client -tls1`) |
| `example.com` | **D** (54) | Valid certificate, SPF/DMARC and DNSSEC, but no security headers, no HTTP→HTTPS redirect, TLS 1.0/1.1 accepted, no CAA or security.txt. Behind Cloudflare, so Shodan's open ports belong to the CDN and aren't penalised |
| `expired.badssl.com` | **F** (16) | Expired certificate, no headers, nginx version exposed, no SPF/DMARC, exposed services per Shodan |
| `httpforever.com` | **F** (capped) | No HTTPS at all |


## Data sources & credits

The Hacker's View uses free, keyless public services. Thank you to:
[Shodan InternetDB](https://internetdb.shodan.io/),
[Have I Been Pwned](https://haveibeenpwned.com/) (breach data, CC BY 4.0, attribution shown on every report),
[rdap.org](https://about.rdap.org/) and the domain registries,
the [Internet Archive Wayback Machine](https://web.archive.org/),
[ipwho.is](https://ipwho.is/), and
[OpenStreetMap](https://www.openstreetmap.org/copyright) contributors (map data) with [Leaflet](https://leafletjs.com/).
Check each service's terms before heavy or commercial use.

## Limitations

This is a quick external check of configuration, not a penetration test: it only looks at the homepage, can't see
pages behind a login, and doesn't test application code. Some sites (or bot protection) serve different headers to
automated clients. The report notes when the final response was an error page.
