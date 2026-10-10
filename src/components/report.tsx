"use client";

import { useMemo } from "react";
import { ClickjackDemo } from "@/components/clickjack-demo";
import { CopyButton } from "@/components/copy";
import { RobotsList, TechnologyList, TlsDetailsPanel } from "@/components/details";
import { AllFixes, FixPanel, PlatformProvider } from "@/components/fix-panel";
import { ChevronIcon, InfoIcon, RefreshIcon } from "@/components/icons";
import { HackersView } from "@/components/hackers-view";
import { TrendBadge } from "@/components/recent-scans";
import { CATEGORY_ICONS, GRADE_STYLES, RichText, STATUS_STYLES, StatusBadge, StatusIcon } from "@/components/ui";
import { buildFixes, type FindingFix, type FixBundle } from "@/lib/fixes";
import type { HistoryEntry } from "@/lib/history";
import type { IntelState } from "@/lib/intel/types";
import { reportToText } from "@/lib/report-text";
import { GRADE_THRESHOLDS } from "@/lib/scanner/scoring";
import type { CategoryResult, Finding, ScanReport } from "@/lib/scanner/types";
import { site } from "@/lib/site";

function GradeBadge({ report }: { report: ScanReport }) {
  const style = GRADE_STYLES[report.grade];
  const r = 52;
  const circumference = 2 * Math.PI * r;
  const dash = (report.score / 100) * circumference;
  return (
    <div className={`relative size-40 shrink-0 animate-pop rounded-full shadow-2xl sm:size-44 ${style.glow}`}>
      <svg viewBox="0 0 120 120" className="size-full -rotate-90">
        <circle cx="60" cy="60" r={r} className="fill-ink-900 stroke-white/[0.07]" strokeWidth="9" />
        <circle
          cx="60"
          cy="60"
          r={r}
          fill="none"
          className={style.stroke}
          strokeWidth="9"
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumference}`}
        />
      </svg>
      <div className="absolute inset-0 grid place-content-center text-center">
        <span className={`text-6xl font-bold leading-none tracking-tight sm:text-7xl ${style.text}`}>
          {report.grade}
        </span>
        <span className="mt-1.5 text-sm font-medium text-slate-400">{report.score} / 100</span>
      </div>
    </div>
  );
}

function Summary({
  report,
  previous,
  intel,
  onReset,
}: {
  report: ScanReport;
  previous: HistoryEntry | null;
  intel: IntelState;
  onReset: () => void;
}) {
  const date = new Date(report.scannedAt);
  return (
    <section
      aria-labelledby="report-title"
      className="animate-fade-up rounded-3xl border border-white/[0.08] bg-ink-900/80 p-6 shadow-xl shadow-black/30 sm:p-8"
    >
      <div className="grid gap-8 lg:grid-cols-[1.2fr_1fr] lg:gap-10">
        <div className="flex flex-col items-center gap-7 text-center md:flex-row md:items-center md:text-left">
          <GradeBadge report={report} />
          <div className="min-w-0 flex-1">
            <p className="text-xs font-medium uppercase tracking-[0.18em] text-indigo-300/80">Security report</p>
            <h2
              id="report-title"
              className="mt-1.5 break-all text-2xl font-semibold tracking-tight text-white sm:text-3xl"
            >
              {report.domain}
            </h2>
            <p className="mt-2 text-sm text-slate-400">
              Scanned {date.toLocaleString()} · {(report.durationMs / 1000).toFixed(1)}s
              {report.ip ? <> · {report.ip}</> : null}
            </p>
            <div className="mt-4 flex flex-wrap justify-center gap-2 md:justify-start">
              {(["pass", "warn", "fail"] as const).map((s) => (
                <span
                  key={s}
                  className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-sm ring-1 ${STATUS_STYLES[s].bg} ${STATUS_STYLES[s].text} ${STATUS_STYLES[s].ring}`}
                >
                  <span className="font-semibold">{report.counts[s]}</span>
                  {s === "pass"
                    ? "passed"
                    : s === "warn"
                      ? report.counts.warn === 1
                        ? "warning"
                        : "warnings"
                      : "failed"}
                </span>
              ))}
            </div>
            {previous && (
              <div className="mt-2.5 flex justify-center md:justify-start">
                <TrendBadge previous={previous} current={report} />
              </div>
            )}
            <div className="mt-6 flex flex-col gap-2.5 sm:flex-row sm:justify-center md:justify-start">
              <CopyButton
                text={() => reportToText(report, site.name, intel)}
                label="Copy report"
                className="rounded-xl bg-white/[0.06] px-4 py-2.5 text-sm font-medium text-slate-100 ring-1 ring-white/10 hover:bg-white/10"
              />
              <button
                type="button"
                onClick={onReset}
                className="inline-flex items-center justify-center gap-2 rounded-xl bg-indigo-500 px-4 py-2.5 text-sm font-medium text-white shadow-lg shadow-indigo-500/20 transition hover:bg-indigo-400 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-300"
              >
                <RefreshIcon className="size-4" />
                Scan another site
              </button>
            </div>
          </div>
        </div>
        <Breakdown report={report} />
      </div>

      {(report.cap || report.notes.length > 0) && (
        <div className="mt-7 space-y-2.5 border-t border-white/[0.06] pt-6">
          {report.cap && (
            <p className="flex gap-2.5 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-400/20">
              <InfoIcon className="mt-0.5 size-4 shrink-0" />
              <span>
                Grade capped at <strong className="font-semibold">{report.cap.grade}</strong> (score alone would be
                higher): {report.cap.reason}
              </span>
            </p>
          )}
          {report.notes.map((note) => (
            <p
              key={note}
              className="flex gap-2.5 rounded-xl bg-white/[0.03] px-4 py-3 text-sm text-slate-300 ring-1 ring-white/[0.06]"
            >
              <InfoIcon className="mt-0.5 size-4 shrink-0 text-sky-300" />
              <span className="min-w-0 break-words">{note}</span>
            </p>
          ))}
        </div>
      )}
    </section>
  );
}

function Breakdown({ report }: { report: ScanReport }) {
  return (
    <section
      aria-labelledby="breakdown-title"
      className="border-t border-white/[0.06] pt-7 lg:border-l lg:border-t-0 lg:pl-10 lg:pt-0"
    >
      <h3 id="breakdown-title" className="text-base font-semibold text-white">
        Score breakdown
      </h3>
      <p className="mt-1 text-sm text-slate-400">
        Each area is weighted by how much it matters for real-world attacks.
      </p>
      <ul className="mt-5 space-y-3.5">
        {report.categories.map((c) => {
          const Icon = CATEGORY_ICONS[c.id];
          const pct = c.maxScore ? (c.score / c.maxScore) * 100 : 0;
          return (
            <li key={c.id}>
              <a
                href={`#cat-${c.id}`}
                className="group block rounded-lg focus-visible:outline-2 focus-visible:outline-indigo-400"
              >
                <div className="flex items-center justify-between gap-3 text-sm">
                  <span className="flex items-center gap-2 text-slate-200 group-hover:text-white">
                    <Icon className="size-4 text-slate-400" />
                    {c.title}
                  </span>
                  <span className="tabular-nums text-slate-400">
                    <span className="font-medium text-slate-100">{formatPoints(c.score)}</span> / {c.maxScore}
                  </span>
                </div>
                <div className="mt-2 h-2 overflow-hidden rounded-full bg-white/[0.06]">
                  <div
                    className={`h-full rounded-full transition-[width] duration-700 ${STATUS_STYLES[c.status].bar}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </a>
            </li>
          );
        })}
      </ul>
      {report.penalties.length > 0 && (
        <ul className="mt-4 space-y-2 border-t border-white/[0.06] pt-4" aria-label="Penalties">
          {report.penalties.map((p) => (
            <li key={p.id} className="flex items-start justify-between gap-3 text-sm">
              <span className="min-w-0 text-slate-300">
                {p.label}
                <span className="block truncate text-xs text-slate-500" title={p.reason}>
                  {p.reason}
                </span>
              </span>
              <span className="shrink-0 font-medium tabular-nums text-rose-300">{p.points}</span>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-6 flex flex-wrap items-center gap-x-3.5 gap-y-2 text-xs text-slate-400">
        <span className="font-medium text-slate-300">Grade scale</span>
        {GRADE_THRESHOLDS.map((t) => (
          <span
            key={t.grade}
            className={
              t.grade === report.grade
                ? `rounded-md bg-white/[0.07] px-2 py-0.5 font-semibold ${GRADE_STYLES[t.grade].text}`
                : ""
            }
          >
            {t.grade} {t.min > 0 ? `≥ ${t.min}` : `< ${GRADE_THRESHOLDS.at(-2)!.min}`}
          </span>
        ))}
      </div>
    </section>
  );
}

function formatPoints(n: number) {
  return Number.isInteger(n) ? String(n) : n.toFixed(1);
}

function FindingRow({ f, fix }: { f: Finding; fix?: FindingFix }) {
  const needsAttention = f.status === "warn" || f.status === "fail";
  const informational = f.maxPoints === 0;
  return (
    <li className="py-1">
      <details open={needsAttention} className="group rounded-xl transition hover:bg-white/[0.02]">
        <summary className="flex cursor-pointer items-start gap-3 rounded-xl px-2 py-3 focus-visible:outline-2 focus-visible:outline-indigo-400 sm:px-3">
          <StatusIcon status={f.status} className="size-3.5" />
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-0.5">
              <span className="font-medium text-slate-100">{f.title}</span>
              <span className="text-xs tabular-nums text-slate-500">
                {informational ? "info · not scored" : `${formatPoints(f.points)}/${f.maxPoints} pts`}
              </span>
            </div>
            <p className="mt-0.5 break-words text-sm text-slate-400">{f.summary}</p>
          </div>
          <ChevronIcon className="mt-1 size-4 shrink-0 text-slate-500 transition group-open:rotate-90" />
        </summary>
        <div className="space-y-4 pb-4 pl-11 pr-2 text-sm sm:pl-12 sm:pr-3">
          <div>
            <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-500">What it means</h5>
            <p className="mt-1 leading-relaxed text-slate-300">{f.explanation}</p>
          </div>
          {f.fix && (
            <div
              className={`rounded-xl p-3.5 ring-1 ${needsAttention ? "bg-indigo-500/[0.08] ring-indigo-400/20" : "bg-white/[0.03] ring-white/[0.06]"}`}
            >
              <h5 className="text-xs font-semibold uppercase tracking-wider text-indigo-300">
                {needsAttention ? "How to fix" : "Recommendation"}
              </h5>
              <p className="mt-1 leading-relaxed text-slate-200">
                <RichText text={f.fix} />
              </p>
              {fix && needsAttention && (
                <div className="mt-3.5">
                  <FixPanel fix={fix} />
                </div>
              )}
            </div>
          )}
          {f.evidence && (
            <div>
              <h5 className="text-xs font-semibold uppercase tracking-wider text-slate-500">What we saw</h5>
              {/* Raw scanned data: rendered as a text node only, never as HTML. */}
              <pre className="mt-1.5 max-h-52 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-ink-950/80 p-3 font-mono text-xs leading-relaxed text-slate-300 ring-1 ring-white/[0.06]">
                {f.evidence}
              </pre>
            </div>
          )}
        </div>
      </details>
    </li>
  );
}

function CategoryExtras({ id, report }: { id: CategoryResult["id"]; report: ScanReport }) {
  if (id === "tls" && report.details.tls) return <TlsDetailsPanel tls={report.details.tls} />;
  if (id === "leakage") return <TechnologyList technologies={report.details.technologies} />;
  if (id === "files") return <RobotsList robots={report.details.robots} />;
  return null;
}

function CategoryCard({
  c,
  index,
  report,
  fixes,
}: {
  c: CategoryResult;
  index: number;
  report: ScanReport;
  fixes: FixBundle;
}) {
  const Icon = CATEGORY_ICONS[c.id];
  const delay =
    [
      "",
      "[animation-delay:60ms]",
      "[animation-delay:120ms]",
      "[animation-delay:180ms]",
      "[animation-delay:240ms]",
      "[animation-delay:300ms]",
      "[animation-delay:360ms]",
      "[animation-delay:420ms]",
    ][index] ?? "";
  return (
    <section
      id={`cat-${c.id}`}
      aria-labelledby={`cat-${c.id}-title`}
      className={`scroll-mt-24 animate-fade-up rounded-3xl border border-white/[0.08] bg-ink-900/60 p-4 sm:p-6 ${delay}`}
    >
      <header className="flex items-start gap-4 px-2 sm:px-3">
        <span className="grid size-11 shrink-0 place-items-center rounded-2xl bg-white/[0.04] ring-1 ring-white/[0.08]">
          <Icon className="size-5 text-indigo-300" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
            <h3 id={`cat-${c.id}-title`} className="text-lg font-semibold text-white">
              {c.title}
            </h3>
            <StatusBadge status={c.status} />
          </div>
          <p className="mt-1 text-sm text-slate-400">{c.description}</p>
        </div>
        <div className="shrink-0 text-right">
          <span className="text-xl font-semibold tabular-nums text-white">{formatPoints(c.score)}</span>
          <span className="text-sm text-slate-500">/{c.maxScore}</span>
        </div>
      </header>
      <ul className="mt-4 divide-y divide-white/[0.05] border-t border-white/[0.06] pt-1">
        {c.findings.map((f) => (
          <FindingRow key={f.id} f={f} fix={fixes.byFinding[f.id]} />
        ))}
      </ul>
      <CategoryExtras id={c.id} report={report} />
    </section>
  );
}

export function Report({
  report,
  previous,
  intel,
  intelDone,
  onReset,
}: {
  report: ScanReport;
  previous: HistoryEntry | null;
  intel: IntelState;
  intelDone: boolean;
  onReset: () => void;
}) {
  const fixes = useMemo(() => buildFixes(report), [report]);
  return (
    <PlatformProvider>
      <div className="min-w-0 space-y-6">
        <Summary report={report} previous={previous} intel={intel} onReset={onReset} />
        <HackersView domain={report.domain} intel={intel} done={intelDone} penalties={report.penalties} />
        <AllFixes bundle={fixes} />
        {report.details.frame.frameable && <ClickjackDemo host={report.domain} url={report.details.frame.url} />}
        <div className="grid grid-cols-1 gap-6">
          {report.categories.map((c, i) => (
            <CategoryCard key={c.id} c={c} index={i} report={report} fixes={fixes} />
          ))}
        </div>
      </div>
    </PlatformProvider>
  );
}
