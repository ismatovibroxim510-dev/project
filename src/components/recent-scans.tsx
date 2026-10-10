"use client";

import { ClockIcon, TrendDownIcon, TrendUpIcon } from "@/components/icons";
import { GRADE_STYLES } from "@/components/ui";
import {
  clearHistory,
  compareScans,
  latestPerDomain,
  useScanHistory,
  type HistoryEntry,
  type Trend,
} from "@/lib/history";

export function TrendBadge({
  previous,
  current,
}: {
  previous: HistoryEntry;
  current: Pick<HistoryEntry, "grade" | "score">;
}) {
  const trend = compareScans(previous, current);
  const date = new Date(previous.date).toLocaleDateString(undefined, { month: "short", day: "numeric" });
  const style: Record<Trend, string> = {
    up: "bg-emerald-400/10 text-emerald-200 ring-emerald-400/25",
    down: "bg-rose-500/10 text-rose-200 ring-rose-400/25",
    same: "bg-white/[0.04] text-slate-300 ring-white/[0.08]",
  };
  const Icon = trend === "up" ? TrendUpIcon : trend === "down" ? TrendDownIcon : ClockIcon;
  const text =
    trend === "same"
      ? `No change since ${date} (${previous.grade}, ${previous.score})`
      : `${trend === "up" ? "Up" : "Down"} from ${previous.grade} (${previous.score}) on ${date}`;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-sm ring-1 ${style[trend]}`}>
      <Icon className="size-4" />
      {text}
    </span>
  );
}

export function RecentScans({ onSelect, disabled }: { onSelect: (domain: string) => void; disabled?: boolean }) {
  const history = useScanHistory();
  const items = latestPerDomain(history).slice(0, 8);
  if (!items.length) return null;
  return (
    <section aria-labelledby="recent-title" className="mx-auto mt-8 w-full max-w-2xl">
      <div className="flex items-baseline justify-between gap-3">
        <h2 id="recent-title" className="flex items-center gap-2 text-sm font-semibold text-slate-300">
          <ClockIcon className="size-4 text-slate-500" />
          Recent scans
        </h2>
        <button
          type="button"
          onClick={clearHistory}
          className="text-xs text-slate-500 underline decoration-white/15 underline-offset-4 transition hover:text-slate-300"
        >
          Clear
        </button>
      </div>
      <ul className="mt-3 grid gap-2 sm:grid-cols-2">
        {items.map(({ entry, previous }) => {
          const trend = previous ? compareScans(previous, entry) : null;
          return (
            <li key={entry.domain}>
              <button
                type="button"
                disabled={disabled}
                onClick={() => onSelect(entry.domain)}
                className="flex w-full items-center gap-3 rounded-xl bg-white/[0.03] px-3 py-2.5 text-left ring-1 ring-white/[0.07] transition hover:bg-white/[0.06] focus-visible:outline-2 focus-visible:outline-indigo-400 disabled:opacity-50"
              >
                <span
                  className={`grid size-9 shrink-0 place-items-center rounded-lg bg-ink-900 text-sm font-bold ring-1 ring-white/10 ${GRADE_STYLES[entry.grade].text}`}
                >
                  {entry.grade}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium text-slate-100">{entry.domain}</span>
                  <span className="block text-xs text-slate-500">
                    {new Date(entry.date).toLocaleDateString(undefined, {
                      month: "short",
                      day: "numeric",
                      year: "numeric",
                    })}
                    {" · "}
                    {entry.score}/100
                  </span>
                </span>
                {trend && trend !== "same" && previous && (
                  <span
                    className={`flex items-center gap-1 text-xs ${trend === "up" ? "text-emerald-300" : "text-rose-300"}`}
                    title={`${trend === "up" ? "Up" : "Down"} from ${previous.grade}`}
                  >
                    {trend === "up" ? <TrendUpIcon className="size-4" /> : <TrendDownIcon className="size-4" />}
                    <span className="sr-only">
                      {trend === "up" ? "Up" : "Down"} from {previous.grade}
                    </span>
                    {previous.grade}
                  </span>
                )}
              </button>
            </li>
          );
        })}
      </ul>
      <p className="mt-2 text-xs text-slate-600">Stored only in this browser.</p>
    </section>
  );
}
