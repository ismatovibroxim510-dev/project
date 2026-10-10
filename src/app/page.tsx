import Link from "next/link";
import { Scanner } from "@/components/scanner";
import { CATEGORY_ICONS } from "@/components/ui";
import { GRADE_THRESHOLDS } from "@/lib/scanner/scoring";
import { CATEGORY_META, CATEGORY_ORDER, type CategoryId } from "@/lib/scanner/types";

const CHECK_DETAILS: Record<CategoryId, string[]> = {
  https: ["Site loads over HTTPS", "HTTP redirects to HTTPS"],
  tls: ["Trusted, matching certificate", "Expiry", "TLS 1.0–1.3 support", "Key strength", "Signature", "Chain & SANs"],
  headers: [
    "HSTS",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
  ],
  cookies: ["Secure", "HttpOnly", "SameSite"],
  leakage: ["Server version", "X-Powered-By", "Technology fingerprint"],
  email: ["SPF record", "DMARC policy"],
  dns: ["CAA record", "DNSSEC"],
  files: ["security.txt", "robots.txt"],
};

export default async function Home({ searchParams }: PageProps<"/">) {
  // Shared result links look like /?domain=example.com
  const { domain } = await searchParams;
  const initialDomain = typeof domain === "string" && domain.length <= 253 ? domain : "";

  return (
    <>
      <section className="relative overflow-hidden">
        <div aria-hidden="true" className="bg-grid pointer-events-none absolute inset-0 -z-10" />
        <div className="mx-auto max-w-6xl px-4 pb-16 pt-16 sm:px-6 sm:pt-24">
          <div className="mx-auto max-w-3xl text-center">
            <p className="inline-flex items-center gap-2 rounded-full border border-indigo-400/20 bg-indigo-400/[0.08] px-3.5 py-1 text-xs font-medium text-indigo-200">
              <span className="size-1.5 rounded-full bg-cyan-300" />
              Free · No sign-up · Results in seconds
            </p>
            <h1 className="mt-6 text-balance text-4xl font-semibold tracking-tight text-white sm:text-6xl">
              How secure is your{" "}
              <span className="bg-gradient-to-r from-indigo-300 via-sky-300 to-cyan-200 bg-clip-text text-transparent">
                website
              </span>
              ?
            </h1>
            <p className="mx-auto mt-5 max-w-2xl text-pretty text-base leading-relaxed text-slate-400 sm:text-lg">
              Enter a domain to get an A+ to F security grade. We check HTTPS, the TLS certificate, security headers,
              email spoofing protection and cookies, then explain every issue in plain English with how to fix it.
            </p>
          </div>
          <Scanner initialDomain={initialDomain} />
        </div>
      </section>

      <section aria-labelledby="checks-title" className="mx-auto max-w-6xl px-4 pb-20 sm:px-6">
        <div className="max-w-2xl">
          <h2 id="checks-title" className="text-2xl font-semibold tracking-tight text-white sm:text-3xl">
            What we check
          </h2>
          <p className="mt-3 text-slate-400">
            Eight areas, weighted by how much they matter for real-world attacks. The weights add up to 100 points.
          </p>
        </div>
        <div className="mt-8 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {CATEGORY_ORDER.map((id) => {
            const meta = CATEGORY_META[id];
            const Icon = CATEGORY_ICONS[id];
            return (
              <article
                key={id}
                className="group rounded-2xl border border-white/[0.07] bg-ink-900/50 p-5 transition hover:border-indigo-400/25 hover:bg-ink-900"
              >
                <div className="flex items-center justify-between">
                  <span className="grid size-10 place-items-center rounded-xl bg-white/[0.04] ring-1 ring-white/[0.08] transition group-hover:ring-indigo-400/30">
                    <Icon className="size-5 text-indigo-300" />
                  </span>
                  <span className="rounded-full bg-white/[0.04] px-2.5 py-0.5 text-xs font-medium tabular-nums text-slate-400 ring-1 ring-white/[0.06]">
                    {meta.maxScore} pts
                  </span>
                </div>
                <h3 className="mt-4 font-semibold text-white">{meta.title}</h3>
                <p className="mt-1.5 text-sm leading-relaxed text-slate-400">{meta.description}</p>
                <ul className="mt-4 flex flex-wrap gap-1.5">
                  {CHECK_DETAILS[id].map((d) => (
                    <li
                      key={d}
                      className="rounded-md bg-white/[0.03] px-2 py-0.5 text-xs text-slate-400 ring-1 ring-white/[0.05]"
                    >
                      {d}
                    </li>
                  ))}
                </ul>
              </article>
            );
          })}
        </div>

        <div className="mt-6 flex flex-col gap-4 rounded-2xl border border-white/[0.07] bg-ink-900/50 p-5 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h3 className="font-semibold text-white">How grades work</h3>
            <p className="mt-1 text-sm text-slate-400">
              A+ needs 95+ points and no failed checks. No HTTPS means F; an untrusted certificate caps the grade at D,
              a weak key at C, and accepting TLS 1.0/1.1 at B.{" "}
              <Link
                href="/about#grading"
                className="text-indigo-300 underline decoration-indigo-300/30 underline-offset-4 hover:text-indigo-200"
              >
                Full breakdown
              </Link>
            </p>
          </div>
          <ul className="flex flex-wrap gap-2 text-sm">
            {GRADE_THRESHOLDS.map((t) => (
              <li
                key={t.grade}
                className="rounded-lg bg-white/[0.04] px-2.5 py-1 tabular-nums text-slate-300 ring-1 ring-white/[0.06]"
              >
                <span className="font-semibold text-white">{t.grade}</span> {t.min > 0 ? `${t.min}+` : `<40`}
              </li>
            ))}
          </ul>
        </div>
      </section>
    </>
  );
}
