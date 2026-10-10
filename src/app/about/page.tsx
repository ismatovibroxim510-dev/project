import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRightIcon } from "@/components/icons";
import { CATEGORY_ICONS } from "@/components/ui";
import { GRADE_THRESHOLDS } from "@/lib/scanner/scoring";
import { CATEGORY_META, CATEGORY_ORDER } from "@/lib/scanner/types";
import { EXPOSURE_RULES } from "@/lib/intel/exposure-rules";
import { CHECK_WEIGHTS, GRADE_CAPS } from "@/lib/scanner/weights";
import { site } from "@/lib/site";

export const metadata: Metadata = {
  title: "About",
  description: `Who built ${site.name}, why, and exactly how the security scan and grading work.`,
  alternates: { canonical: "/about" },
  openGraph: { title: `About ${site.name}`, url: "/about" },
};

const SAFEGUARDS = [
  {
    title: "Passive only",
    body: "The scanner behaves like a visitor: it loads the homepage, security.txt and robots.txt, does one ordinary TLS handshake per protocol version, and reads public DNS records. No port scanning, no vulnerability probes, no guessing of paths or passwords. Paths listed in robots.txt are shown, never visited. Open ports and CVEs come from Shodan's existing data, not from scanning.",
  },
  {
    title: "Strict input validation",
    body: "Only real public domain names are accepted. Protocols, paths, ports and credentials are stripped; IP addresses and internal names like localhost or .internal are rejected.",
  },
  {
    title: "SSRF protection on every connection",
    body: "Every connection, including each redirect and every TLS handshake, resolves DNS and refuses private, loopback, link-local and reserved ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x, ::1, fc00::/7…). The check runs inside the socket's own lookup, so DNS rebinding can't sneak in a different address.",
  },
  {
    title: "Hard limits",
    body: "Each network request times out after 5 seconds, at most 5 redirects are followed, and only ports 80 and 443 are contacted. The only bodies ever read are security.txt (max 32 KB) and robots.txt (max 64 KB), as plain text.",
  },
  {
    title: "Legacy TLS stays contained",
    body: "Testing for TLS 1.0/1.1 needs OpenSSL's security level lowered. That setting is used only for those single test handshakes, which send no data; every other connection uses normal, modern settings.",
  },
  {
    title: "Rate limiting",
    body: "Each visitor can run a limited number of scans per few minutes, so the scanner can't be turned into a tool for flooding other sites.",
  },
  {
    title: "No XSS from scanned sites",
    body: "Header values, DNS records and file contents from scanned sites are displayed strictly as text, never as HTML. The app itself ships a nonce-based Content-Security-Policy.",
  },
  {
    title: "Contained clickjacking demo",
    body: 'The demo embeds the scanned page with sandbox="" (no scripts, forms or navigation). Our pages may only frame our own demo page, whose policy, set per request, allows exactly one origin: the site you scanned.',
  },
  {
    title: "Third-party data is untrusted",
    body: "Responses from public data sources are fetched over verified HTTPS through the same SSRF-guarded client (5s timeouts, size caps), strictly validated, shortened, and shown as plain text. HTML in breach descriptions is stripped. Results are cached for up to 24 hours, and a source that fails or is rate-limited is simply hidden.",
  },
  {
    title: "No tracking, no server storage",
    body: "There's no database. Results exist only in your browser tab, recent scans are saved only in your browser's local storage, and cookie values from scanned sites are discarded.",
  },
];

const DATA_SOURCES = [
  {
    name: "Shodan InternetDB",
    href: "https://internetdb.shodan.io/",
    what: "Open ports, known CVEs, software (CPEs) and tags for up to two of the site's IP addresses, from Shodan's own earlier internet-wide scans.",
  },
  {
    name: "Have I Been Pwned",
    href: "https://haveibeenpwned.com/",
    what: "Public data breaches of the domain: when, how many accounts, and what was leaked. Licensed CC BY 4.0. Shown as context only; it never affects the grade.",
  },
  {
    name: "RDAP (via rdap.org)",
    href: "https://about.rdap.org/",
    what: "Domain registration date, expiry, last update and registrar, from the official registry. Very new or soon-expiring domains get a warning.",
  },
  {
    name: "Internet Archive Wayback Machine",
    href: "https://web.archive.org/",
    what: "When the site was first archived, the latest snapshot and roughly how many snapshots exist.",
  },
  {
    name: "ipwho.is",
    href: "https://ipwho.is/",
    what: "Approximate server location, hosting provider and network (ASN) of the site's IP address.",
  },
  {
    name: "OpenStreetMap",
    href: "https://www.openstreetmap.org/copyright",
    what: "Map tiles for the server-location map (© OpenStreetMap contributors), displayed with the open-source Leaflet library.",
  },
];

export default function AboutPage() {
  return (
    <div className="relative">
      <div aria-hidden="true" className="bg-grid pointer-events-none absolute inset-x-0 top-0 -z-10 h-96" />
      <article className="mx-auto max-w-3xl px-4 pb-24 pt-16 sm:px-6 sm:pt-20">
        <p className="text-xs font-medium uppercase tracking-[0.18em] text-indigo-300/80">About</p>
        <h1 className="mt-3 text-balance text-4xl font-semibold tracking-tight text-white sm:text-5xl">
          Security checks anyone can understand
        </h1>

        <section className="mt-12" aria-labelledby="who">
          <h2 id="who" className="text-xl font-semibold text-white">
            Who built this
          </h2>
          <div className="mt-4 space-y-4 leading-relaxed text-slate-300">
            <p>
              Hi, I&apos;m <strong className="font-semibold text-white">Ibrohim</strong>, a student interested in
              cybersecurity. I built {site.name} as a hands-on project to learn how websites are actually protected,
              from TLS certificates to HTTP security headers and email authentication.
            </p>
          </div>
        </section>

        <section className="mt-12" aria-labelledby="why">
          <h2 id="why" className="text-xl font-semibold text-white">
            Why
          </h2>
          <div className="mt-4 space-y-4 leading-relaxed text-slate-300">
            <p>
              Many of the most common website weaknesses aren&apos;t complicated bugs. They&apos;re missing settings: a
              header that was never added, a certificate about to expire, a domain anyone can send email from.
              They&apos;re easy to fix once you know about them, but most tools either assume you&apos;re a security
              expert or bury the answer in jargon.
            </p>
            <p>
              {site.name} gives a clear grade, explains what each result means in plain English, and tells you exactly
              what to change.
            </p>
          </div>
        </section>

        <section className="mt-12" aria-labelledby="how">
          <h2 id="how" className="text-xl font-semibold text-white">
            How it works
          </h2>
          <p className="mt-4 leading-relaxed text-slate-300">
            When you enter a domain, the server connects to it the same way a browser would and reads only public
            information: the homepage&apos;s HTTP response headers (over HTTPS and HTTP), the TLS certificate, one
            handshake per TLS version to see which ones are accepted, the public security.txt and robots.txt files, and
            DNS records (SPF, DMARC, CAA, DNSSEC). Everything runs in parallel and usually takes a few seconds.
          </p>
          <p className="mt-4 leading-relaxed text-slate-300">
            For every problem, the report explains what it means and gives ready-to-paste configuration for nginx,
            Apache, Vercel, Netlify, Cloudflare and Next.js, plus DNS records, generated from what was actually missing.
          </p>
        </section>

        <section className="mt-12" aria-labelledby="grading">
          <h2 id="grading" className="text-xl font-semibold text-white">
            How grading works
          </h2>
          <p className="mt-4 leading-relaxed text-slate-300">
            Each check is a <em>pass</em> (full points), <em>warning</em> (partial points) or <em>fail</em> (no points).
            Weights reflect real-world impact: things every visitor depends on (HTTPS, a trusted certificate, browser
            protections) count most; defence-in-depth extras like CAA, DNSSEC and security.txt count a little.
            Informational findings never change the score.
          </p>
          <div className="mt-6 grid gap-3 sm:grid-cols-2">
            {CATEGORY_ORDER.map((id) => {
              const Icon = CATEGORY_ICONS[id];
              const meta = CATEGORY_META[id];
              return (
                <div key={id} className="rounded-2xl border border-white/[0.08] bg-ink-900/50 p-4">
                  <div className="flex items-center justify-between gap-3">
                    <h3 className="flex items-center gap-2 font-medium text-white">
                      <Icon className="size-4 text-indigo-300" />
                      {meta.title}
                    </h3>
                    <span className="shrink-0 rounded-full bg-white/[0.05] px-2.5 py-0.5 text-xs font-semibold tabular-nums text-slate-200">
                      {meta.maxScore} pts
                    </span>
                  </div>
                  <ul className="mt-3 space-y-1.5 text-sm">
                    {CHECK_WEIGHTS[id].map((c) => (
                      <li key={c.id} className="flex justify-between gap-3 text-slate-400">
                        <span>{c.label}</span>
                        <span className="shrink-0 tabular-nums text-slate-300">{c.points || "info"}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              );
            })}
          </div>
          <div className="mt-6 space-y-4 leading-relaxed text-slate-300">
            <p>
              The total out of 100 becomes a letter grade:{" "}
              {GRADE_THRESHOLDS.map((t, i) => (
                <span key={t.grade}>
                  {i > 0 && (i === GRADE_THRESHOLDS.length - 1 ? " or " : ", ")}
                  <strong className="font-semibold text-white">{t.grade}</strong>
                  {t.min > 0 ? ` (${t.min}+${t.grade === "A+" ? ", with no failed checks" : ""})` : " below that"}
                </span>
              ))}
              .
            </p>
            <p>Some problems are serious enough to cap the grade no matter how good the rest is:</p>
            <ul className="space-y-1.5">
              {GRADE_CAPS.map((c) => (
                <li key={c.grade + c.when} className="flex gap-2.5">
                  <span className="mt-0.5 grid size-6 shrink-0 place-items-center rounded-md bg-white/[0.06] text-xs font-bold text-white">
                    {c.grade}
                  </span>
                  <span>at most, when {c.when}.</span>
                </li>
              ))}
            </ul>
            <p>
              Public exposure data from Shodan can also subtract points (never more than {EXPOSURE_RULES.totalCap} in
              total): <strong className="font-semibold text-white">−{EXPOSURE_RULES.databasePort}</strong> for each
              database reachable from the internet (MySQL, PostgreSQL, Redis, MongoDB…),{" "}
              <strong className="font-semibold text-white">−{EXPOSURE_RULES.remoteAdminPort}</strong> for each
              remote-admin service (SSH, RDP, VNC, Telnet, SMB…), capped at −{EXPOSURE_RULES.portCap} for ports, and{" "}
              <strong className="font-semibold text-white">−{EXPOSURE_RULES.someCves}</strong> for known CVEs (−
              {EXPOSURE_RULES.manyCves} for {EXPOSURE_RULES.manyCvesThreshold} or more). A site with any penalty
              can&apos;t get an A+. If Shodan has no data or can&apos;t be reached, nothing is deducted. Past data
              breaches are shown for context and never change the grade.
            </p>
          </div>
        </section>

        <section className="mt-12" aria-labelledby="sources">
          <h2 id="sources" className="text-xl font-semibold text-white">
            Hacker&apos;s View: public data sources
          </h2>
          <p className="mt-4 leading-relaxed text-slate-300">
            Attackers usually start with reconnaissance from free public sources, so the report shows what they would
            find. <strong className="font-semibold text-white">All of this data is public and passive</strong>: these
            services collected it earlier, and looking it up never touches the scanned server. To look things up, the
            scanned domain and its IP address are sent to the services below. Many thanks to them:
          </p>
          <ul className="mt-6 divide-y divide-white/[0.06] rounded-2xl border border-white/[0.08] bg-ink-900/50">
            {DATA_SOURCES.map((d) => (
              <li key={d.name} className="p-4 sm:p-5">
                <a
                  href={d.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="font-medium text-indigo-300 underline decoration-indigo-300/30 underline-offset-4 hover:text-indigo-200"
                >
                  {d.name}
                </a>
                <p className="mt-1 text-sm text-slate-400">{d.what}</p>
              </li>
            ))}
          </ul>
        </section>

        <section className="mt-12" aria-labelledby="limits">
          <h2 id="limits" className="text-xl font-semibold text-white">
            Limitations
          </h2>
          <p className="mt-4 leading-relaxed text-slate-300">
            This is a quick external check of configuration, not a penetration test. It only looks at the homepage,
            can&apos;t see pages behind a login, and doesn&apos;t look for vulnerabilities in the application&apos;s
            code. Some sites also serve different headers to automated tools. A good grade means the basics are in
            place, not that a site is unbreakable.
          </p>
        </section>

        <section className="mt-12" aria-labelledby="safety">
          <h2 id="safety" className="text-xl font-semibold text-white">
            How the scanner protects itself
          </h2>
          <p className="mt-4 leading-relaxed text-slate-300">
            A tool that makes requests to any URL you give it is itself a juicy target. These are the safeguards built
            in:
          </p>
          <div className="mt-6 grid gap-4 sm:grid-cols-2">
            {SAFEGUARDS.map((s) => (
              <div key={s.title} className="rounded-2xl border border-white/[0.07] bg-ink-900/50 p-5">
                <h3 className="font-medium text-white">{s.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-slate-400">{s.body}</p>
              </div>
            ))}
          </div>
        </section>

        <div className="mt-14">
          <Link
            href="/"
            className="inline-flex items-center gap-2 rounded-xl bg-indigo-500 px-5 py-3 font-semibold text-white shadow-lg shadow-indigo-500/25 transition hover:bg-indigo-400 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-300"
          >
            Scan a website
            <ArrowRightIcon className="size-5" />
          </Link>
        </div>
      </article>
    </div>
  );
}
