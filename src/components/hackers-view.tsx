"use client";

import dynamic from "next/dynamic";
import type { ReactNode } from "react";
import { AlertIcon, ClockIcon, DnsIcon, EyeOffIcon, GlobeIcon, InfoIcon, LockIcon } from "@/components/icons";
import { humanAge, domainAgeDays, rdapWarnings } from "@/lib/intel/rdap-shared";
import { snapshotUrl, timestampToDate } from "@/lib/intel/wayback-shared";
import type { BreachIntel, GeoIntel, IntelState, RdapIntel, ShodanIntel, WaybackIntel } from "@/lib/intel/types";
import type { Penalty } from "@/lib/scanner/types";

const ServerMap = dynamic(() => import("@/components/server-map").then((m) => m.ServerMap), {
  ssr: false,
  loading: () => <div className="h-56 animate-pulse rounded-xl bg-white/[0.04] sm:h-64" />,
});

const CVE_RE = /^CVE-\d{4}-\d{4,7}$/;
const nf = new Intl.NumberFormat("en-US");
// Source dates are UTC (and breach dates are date-only), so format in UTC to avoid off-by-one-day shifts.
const fmtDate = (iso: string) =>
  new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric", timeZone: "UTC" });

function ExternalLink({ href, children }: { href: string; children: ReactNode }) {
  return (
    <a
      href={href}
      target="_blank"
      rel="noopener noreferrer"
      className="text-indigo-300 underline decoration-indigo-300/30 underline-offset-4 hover:text-indigo-200"
    >
      {children}
    </a>
  );
}

function Card({
  title,
  icon,
  credit,
  children,
  wide,
}: {
  title: string;
  icon: ReactNode;
  credit: ReactNode;
  children: ReactNode;
  wide?: boolean;
}) {
  return (
    <article
      className={`flex min-w-0 animate-fade-up flex-col rounded-2xl border border-white/[0.08] bg-ink-900/70 p-5 ${wide ? "lg:col-span-2" : ""}`}
    >
      <h4 className="flex items-center gap-2.5 font-semibold text-white">
        <span className="grid size-8 place-items-center rounded-lg bg-white/[0.05] ring-1 ring-white/[0.08]">
          {icon}
        </span>
        {title}
      </h4>
      <div className="mt-4 min-w-0 flex-1 space-y-4 text-sm">{children}</div>
      <p className="mt-4 border-t border-white/[0.06] pt-3 text-xs text-slate-500">{credit}</p>
    </article>
  );
}

function Skeleton({ title }: { title: string }) {
  return (
    <div className="rounded-2xl border border-white/[0.06] bg-ink-900/40 p-5" aria-busy="true">
      <p className="flex items-center gap-2 text-sm font-medium text-slate-400">
        <span className="size-2 animate-pulse rounded-full bg-indigo-300" />
        {title}
      </p>
      <div className="mt-4 space-y-2">
        <div className="h-3 w-3/4 animate-pulse rounded bg-white/[0.05]" />
        <div className="h-3 w-1/2 animate-pulse rounded bg-white/[0.05]" />
        <div className="h-3 w-2/3 animate-pulse rounded bg-white/[0.05]" />
      </div>
    </div>
  );
}

function Chip({
  children,
  tone = "neutral",
  mono,
}: {
  children: ReactNode;
  tone?: "neutral" | "danger" | "warn";
  mono?: boolean;
}) {
  const tones = {
    neutral: "bg-white/[0.04] text-slate-300 ring-white/[0.07]",
    danger: "bg-rose-500/10 text-rose-200 ring-rose-400/25",
    warn: "bg-amber-400/10 text-amber-100 ring-amber-400/25",
  };
  return (
    <span
      className={`inline-flex max-w-full items-center truncate rounded-md px-2 py-0.5 text-xs ring-1 ${tones[tone]} ${mono ? "font-mono" : ""}`}
    >
      {children}
    </span>
  );
}

function Warning({ children }: { children: ReactNode }) {
  return (
    <p className="flex gap-2 rounded-xl bg-amber-400/10 px-3 py-2.5 text-amber-100 ring-1 ring-amber-400/25">
      <AlertIcon className="mt-0.5 size-4 shrink-0 text-amber-300" />
      <span>{children}</span>
    </p>
  );
}

function ExposureCard({ data, penalties }: { data: ShodanIntel; penalties: Penalty[] }) {
  const impact = penalties
    .filter((p) => p.id === "exposed-ports" || p.id === "known-cves")
    .reduce((s, p) => s + p.points, 0);
  const isCdn = data.hosts.some((h) => h.tags.includes("cdn"));
  return (
    <Card
      wide
      title="Exposed services"
      icon={<EyeOffIcon className="size-4 text-rose-300" />}
      credit={
        <>
          Data from Shodan&apos;s existing public scans. We did not scan this server. Source:{" "}
          <ExternalLink href="https://internetdb.shodan.io/">Shodan InternetDB</ExternalLink>.
        </>
      }
    >
      {data.hosts.length === 0 && (
        <p className="text-slate-300">Shodan has no records for this server&apos;s IP address.</p>
      )}
      {isCdn && (
        <p className="flex gap-2 text-slate-400">
          <InfoIcon className="mt-0.5 size-4 shrink-0 text-sky-300" />
          This IP belongs to a CDN, so these results describe the CDN&apos;s edge server; the site&apos;s real server is
          hidden behind it.
        </p>
      )}
      {data.hosts.map((h) => (
        <div key={h.ip} className="space-y-3">
          <p className="font-mono text-xs text-slate-500">{h.ip}</p>
          {h.ports.length > 0 && (
            <ul className="grid gap-1.5 sm:grid-cols-2">
              {h.ports.map((p) => (
                <li
                  key={p.port}
                  className={`flex items-center gap-2.5 rounded-lg px-3 py-2 ring-1 ${p.highRisk ? "bg-rose-500/[0.08] ring-rose-400/25" : "bg-white/[0.03] ring-white/[0.06]"}`}
                >
                  <span
                    className={`w-12 shrink-0 font-mono text-sm tabular-nums ${p.highRisk ? "text-rose-200" : "text-slate-300"}`}
                  >
                    {p.port}
                  </span>
                  <span className="min-w-0 flex-1 truncate text-slate-200">{p.label}</span>
                  {p.highRisk && (
                    <span className="shrink-0 text-[11px] font-semibold uppercase tracking-wide text-rose-300">
                      High risk
                    </span>
                  )}
                </li>
              ))}
            </ul>
          )}
          {h.ports.some((p) => p.highRisk) && (
            <p className="text-slate-400">
              {h.ports.some((p) => p.highRisk && p.kind === "database")
                ? "Databases should never be reachable from the internet: bots constantly scan for them and try default or leaked passwords. "
                : ""}
              Remote-admin services (SSH, RDP, VNC…) are brute-forced around the clock; restrict them to a VPN or
              allow-listed IPs with a firewall.
            </p>
          )}
          {h.cveTotal > 0 && (
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                Known vulnerabilities ({h.cveTotal})
              </p>
              <ul className="mt-2 flex flex-wrap gap-1.5">
                {h.cves
                  .filter((id) => CVE_RE.test(id))
                  .map((id) => (
                    <li key={id}>
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-block rounded-md bg-rose-500/10 px-2 py-0.5 font-mono text-xs text-rose-200 ring-1 ring-rose-400/25 hover:bg-rose-500/20"
                      >
                        {id}
                      </a>
                    </li>
                  ))}
                {h.cveTotal > h.cves.length && (
                  <li className="px-1 text-xs text-slate-500">and {h.cveTotal - h.cves.length} more</li>
                )}
              </ul>
              <p className="mt-2 text-xs text-slate-500">
                Matched from software versions Shodan saw; some may already be patched (backported fixes).
              </p>
            </div>
          )}
          {(h.cpes.length > 0 || h.tags.length > 0) && (
            <div className="flex flex-wrap gap-1.5">
              {h.cpes.map((c) => (
                <Chip key={c} mono>
                  {c.replace(/^cpe:\/[aho]:/, "")}
                </Chip>
              ))}
              {h.tags.map((t) => (
                <Chip key={t}>{t}</Chip>
              ))}
            </div>
          )}
        </div>
      ))}
      {data.noData.length > 0 && data.hosts.length > 0 && (
        <p className="text-xs text-slate-500">No Shodan records for {data.noData.join(", ")}.</p>
      )}
      <p className={impact < 0 ? "font-medium text-rose-200" : "text-slate-400"}>
        {impact < 0
          ? `Score impact: ${impact} points (see the score breakdown).`
          : "No high-risk services or known CVEs: no score impact."}
      </p>
    </Card>
  );
}

function BreachesCard({ data }: { data: BreachIntel }) {
  return (
    <Card
      wide
      title="Past data breaches"
      icon={<LockIcon className="size-4 text-amber-300" />}
      credit={
        <>
          Breach data from <ExternalLink href="https://haveibeenpwned.com/">Have I Been Pwned</ExternalLink> (CC BY
          4.0). Shown for context; it doesn&apos;t change the grade.
        </>
      }
    >
      {data.breaches.length === 0 ? (
        <p className="text-slate-300">No known public breaches for this domain.</p>
      ) : (
        <ul className="space-y-3">
          {data.breaches.map((b) => (
            <li key={b.name} className="rounded-xl bg-white/[0.03] p-3 ring-1 ring-white/[0.06]">
              <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
                <span className="font-medium text-white">{b.title}</span>
                <span className="text-xs text-slate-500">{b.date ? fmtDate(b.date) : "date unknown"}</span>
              </div>
              <p className="mt-1 text-slate-300">
                {nf.format(b.pwnCount)} accounts ·{" "}
                <span className={b.verified ? "text-slate-300" : "text-amber-200"}>
                  {b.verified ? "verified" : "unverified"}
                </span>
              </p>
              {b.dataClasses.length > 0 && (
                <div className="mt-2 flex flex-wrap gap-1.5">
                  {b.dataClasses.map((c) => (
                    <Chip key={c} tone={/password/i.test(c) ? "danger" : "neutral"}>
                      {c}
                    </Chip>
                  ))}
                </div>
              )}
              {b.description && (
                <p className="mt-2 line-clamp-3 text-xs leading-relaxed text-slate-400">{b.description}</p>
              )}
            </li>
          ))}
          {data.total > data.breaches.length && (
            <li className="text-xs text-slate-500">and {data.total - data.breaches.length} more</li>
          )}
        </ul>
      )}
    </Card>
  );
}

function DomainAgeCard({ data }: { data: RdapIntel }) {
  const age = domainAgeDays(data.registered);
  const warnings = rdapWarnings(data);
  const rows: Array<[string, string | null]> = [
    ["Registered", data.registered && fmtDate(data.registered)],
    ["Expires", data.expires && fmtDate(data.expires)],
    ["Last updated", data.updated && fmtDate(data.updated)],
    ["Registrar", data.registrar],
  ];
  return (
    <Card
      title="Domain age"
      icon={<DnsIcon className="size-4 text-indigo-300" />}
      credit={
        <>
          Registration data via <ExternalLink href="https://about.rdap.org/">RDAP</ExternalLink> (rdap.org and the
          domain&apos;s registry).
        </>
      }
    >
      {age !== null && <p className="text-2xl font-semibold tracking-tight text-white">{humanAge(age)}</p>}
      <dl className="space-y-1.5">
        {rows
          .filter(([, v]) => v)
          .map(([k, v]) => (
            <div key={k} className="flex justify-between gap-3">
              <dt className="text-slate-500">{k}</dt>
              <dd className="min-w-0 truncate text-right text-slate-200">{v}</dd>
            </div>
          ))}
      </dl>
      {warnings.map((w) => (
        <Warning key={w.id}>{w.text}</Warning>
      ))}
    </Card>
  );
}

function HistoryCard({ data }: { data: WaybackIntel }) {
  const first = data.firstTimestamp ? timestampToDate(data.firstTimestamp) : null;
  const last = data.lastTimestamp ? timestampToDate(data.lastTimestamp) : null;
  return (
    <Card
      title="Site history"
      icon={<ClockIcon className="size-4 text-indigo-300" />}
      credit={
        <>
          Snapshots from the{" "}
          <ExternalLink href="https://web.archive.org/">Internet Archive Wayback Machine</ExternalLink>.
        </>
      }
    >
      {first && data.firstTimestamp ? (
        <>
          <p className="text-2xl font-semibold tracking-tight text-white">First seen in {first.getUTCFullYear()}</p>
          <dl className="space-y-1.5">
            <div className="flex justify-between gap-3">
              <dt className="text-slate-500">Oldest snapshot</dt>
              <dd className="text-right">
                <ExternalLink href={snapshotUrl(data.firstTimestamp, data.domain)}>
                  {fmtDate(first.toISOString())}
                </ExternalLink>
              </dd>
            </div>
            {last && data.lastTimestamp && (
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Latest snapshot</dt>
                <dd className="text-right">
                  <ExternalLink href={snapshotUrl(data.lastTimestamp, data.domain)}>
                    {fmtDate(last.toISOString())}
                  </ExternalLink>
                </dd>
              </div>
            )}
            {data.captures !== null && data.captures > 0 && (
              <div className="flex justify-between gap-3">
                <dt className="text-slate-500">Snapshots</dt>
                <dd className="text-slate-200">about {nf.format(data.captures)}</dd>
              </div>
            )}
          </dl>
          <p className="text-slate-400">
            Old snapshots can reveal pages, files and contact details that were later removed from the live site.
          </p>
        </>
      ) : (
        <p className="text-slate-300">The Wayback Machine hasn&apos;t archived this site yet.</p>
      )}
    </Card>
  );
}

function flagEmoji(code: string | null): string {
  if (!code || !/^[A-Z]{2}$/.test(code)) return "";
  return String.fromCodePoint(...[...code].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65));
}

function LocationCard({ data }: { data: GeoIntel }) {
  const place = [data.city, data.region, data.country].filter(Boolean).join(", ");
  return (
    <Card
      wide
      title="Server location"
      icon={<GlobeIcon className="size-4 text-indigo-300" />}
      credit={
        <>
          Approximate location from <ExternalLink href="https://ipwho.is/">ipwho.is</ExternalLink>. Map data ©{" "}
          <ExternalLink href="https://www.openstreetmap.org/copyright">OpenStreetMap</ExternalLink> contributors.
        </>
      }
    >
      <div className="grid gap-4 md:grid-cols-[1fr_1.4fr] md:items-start">
        <dl className="space-y-1.5">
          {place && (
            <div>
              <dt className="sr-only">Location</dt>
              <dd className="text-lg font-semibold text-white">
                {flagEmoji(data.countryCode)} {place}
              </dd>
            </div>
          )}
          <div className="flex justify-between gap-3">
            <dt className="text-slate-500">IP address</dt>
            <dd className="font-mono text-slate-200">{data.ip}</dd>
          </div>
          {(data.org || data.isp) && (
            <div className="flex justify-between gap-3">
              <dt className="text-slate-500">Hosting provider</dt>
              <dd className="min-w-0 truncate text-right text-slate-200">{data.org ?? data.isp}</dd>
            </div>
          )}
          {data.asn && (
            <div className="flex justify-between gap-3">
              <dt className="text-slate-500">Network (ASN)</dt>
              <dd className="font-mono text-slate-200">AS{data.asn}</dd>
            </div>
          )}
          <p className="pt-2 text-slate-400">
            Knowing the hosting provider tells an attacker which cloud or data center to target and which abuse contact
            to expect. Sites behind a CDN show the CDN&apos;s location instead.
          </p>
        </dl>
        {data.latitude !== null && data.longitude !== null && (
          <ServerMap latitude={data.latitude} longitude={data.longitude} label={place || data.ip} />
        )}
      </div>
    </Card>
  );
}

const TITLES = {
  shodan: "Checking Shodan for exposed services…",
  breaches: "Searching breach records…",
  rdap: "Looking up domain registration…",
  wayback: "Searching the Wayback Machine…",
  geo: "Locating the server…",
} as const;

export function HackersView({
  domain,
  intel,
  done,
  penalties,
}: {
  domain: string;
  intel: IntelState;
  done: boolean;
  penalties: Penalty[];
}) {
  const loading = (k: keyof IntelState) => intel[k] === undefined && !done;
  const anyVisible = (Object.keys(TITLES) as Array<keyof IntelState>).some((k) => intel[k] || loading(k));
  if (!anyVisible) return null;

  const slot = <K extends keyof IntelState>(
    k: K,
    render: (d: NonNullable<IntelState[K]>) => ReactNode,
    wide = false,
  ) => {
    const d = intel[k];
    if (d) return render(d as NonNullable<IntelState[K]>);
    if (loading(k))
      return (
        <div className={wide ? "lg:col-span-2" : ""}>
          <Skeleton title={TITLES[k]} />
        </div>
      );
    return null; // unavailable: hide the card
  };

  return (
    <section
      aria-labelledby="hackers-view-title"
      className="animate-fade-up rounded-3xl border border-white/[0.08] bg-gradient-to-b from-slate-500/[0.06] to-ink-900/60 p-5 sm:p-7"
    >
      <div className="max-w-3xl">
        <p className="text-xs font-medium uppercase tracking-[0.18em] text-rose-300/80">Hacker&apos;s View</p>
        <h3 id="hackers-view-title" className="mt-1.5 text-xl font-semibold text-white">
          What an attacker can learn about {domain}
        </h3>
        <p className="mt-2 text-sm leading-relaxed text-slate-400">
          Attackers start with reconnaissance from free public sources, without ever touching the target. This is what
          they&apos;d find. All data is public and was collected passively; we didn&apos;t scan or probe the server.
        </p>
      </div>
      <div className="mt-6 grid grid-cols-1 gap-4 lg:grid-cols-2" aria-live="polite">
        {slot(
          "shodan",
          (d) => (
            <ExposureCard data={d} penalties={penalties} />
          ),
          true,
        )}
        {slot("rdap", (d) => (
          <DomainAgeCard data={d} />
        ))}
        {slot("wayback", (d) => (
          <HistoryCard data={d} />
        ))}
        {slot(
          "breaches",
          (d) => (
            <BreachesCard data={d} />
          ),
          true,
        )}
        {slot(
          "geo",
          (d) => (
            <LocationCard data={d} />
          ),
          true,
        )}
      </div>
    </section>
  );
}
