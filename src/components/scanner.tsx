"use client";

import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { AlertIcon, ArrowRightIcon, CheckIcon, GlobeIcon, SpinnerIcon } from "@/components/icons";
import { RecentScans } from "@/components/recent-scans";
import { Report } from "@/components/report";
import { CATEGORY_ICONS, STATUS_STYLES } from "@/components/ui";
import { recordScan, type HistoryEntry } from "@/lib/history";
import type { IntelState } from "@/lib/intel/types";
import {
  CATEGORY_META,
  CATEGORY_ORDER,
  type CategoryId,
  type ScanEvent,
  type ScanReport,
  type Status,
} from "@/lib/scanner/types";

type Phase = "idle" | "scanning" | "done" | "error";

const RUNNING_TEXT: Record<CategoryId, string> = {
  https: "Connecting over HTTPS and HTTP…",
  tls: "Inspecting the certificate and testing TLS 1.0–1.3…",
  headers: "Analysing security headers…",
  leakage: "Looking for version leaks…",
  email: "Querying SPF and DMARC records…",
  cookies: "Checking cookie flags…",
  dns: "Checking CAA records and DNSSEC…",
  files: "Reading security.txt and robots.txt…",
};

/** Minimum gap between ticks so fast checks still visibly tick off one by one. */
const TICK_MS = 280;

function ScanProgress({ domain, ticked }: { domain: string; ticked: Map<CategoryId, Status> }) {
  const doneCount = ticked.size;
  const pct = (doneCount / CATEGORY_ORDER.length) * 100;
  return (
    <section
      aria-labelledby="progress-title"
      className="mx-auto max-w-2xl animate-fade-up rounded-3xl border border-white/[0.08] bg-ink-900/80 p-6 shadow-xl shadow-black/30 sm:p-8"
    >
      <div className="flex items-center justify-between gap-4">
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-[0.18em] text-indigo-300/80">Scanning</p>
          <h2 id="progress-title" className="mt-1 truncate text-xl font-semibold text-white">
            {domain}
          </h2>
        </div>
        <span className="shrink-0 text-sm tabular-nums text-slate-400">
          {doneCount}/{CATEGORY_ORDER.length}
        </span>
      </div>
      <div
        className="mt-5 h-1.5 overflow-hidden rounded-full bg-white/[0.06]"
        role="progressbar"
        aria-valuemin={0}
        aria-valuemax={CATEGORY_ORDER.length}
        aria-valuenow={doneCount}
        aria-label="Scan progress"
      >
        <div
          className="h-full rounded-full bg-gradient-to-r from-indigo-500 to-cyan-400 transition-[width] duration-500 ease-out"
          style={{ width: `${Math.max(pct, 4)}%` }}
        />
      </div>
      <ul className="mt-6 space-y-1" aria-live="polite">
        {CATEGORY_ORDER.map((id) => {
          const status = ticked.get(id);
          const Icon = CATEGORY_ICONS[id];
          return (
            <li
              key={id}
              className={`flex items-center gap-3.5 rounded-xl px-3 py-2.5 transition-colors ${status ? "bg-white/[0.025]" : ""}`}
            >
              <Icon className={`size-5 shrink-0 ${status ? "text-slate-300" : "text-slate-500"}`} />
              <div className="min-w-0 flex-1">
                <p className={`text-sm font-medium ${status ? "text-slate-100" : "text-slate-300"}`}>
                  {CATEGORY_META[id].title}
                </p>
                <p className="truncate text-xs text-slate-500">
                  {status
                    ? status === "pass"
                      ? "Looks good"
                      : status === "warn"
                        ? "Needs attention"
                        : "Problems found"
                    : RUNNING_TEXT[id]}
                </p>
              </div>
              {status ? (
                <span
                  className={`grid size-6 animate-pop place-items-center rounded-full ring-1 ${STATUS_STYLES[status].bg} ${STATUS_STYLES[status].text} ${STATUS_STYLES[status].ring}`}
                >
                  {status === "pass" ? (
                    <CheckIcon className="size-3.5" strokeWidth={2.6} />
                  ) : (
                    <span className="text-xs font-bold">!</span>
                  )}
                  <span className="sr-only">
                    {CATEGORY_META[id].title}: {STATUS_STYLES[status].label}
                  </span>
                </span>
              ) : (
                <SpinnerIcon className="size-5 animate-spin text-indigo-300/70" />
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

export function Scanner({ initialDomain = "" }: { initialDomain?: string }) {
  const [input, setInput] = useState(initialDomain);
  const [phase, setPhase] = useState<Phase>("idle");
  const [scanningDomain, setScanningDomain] = useState("");
  const [ticked, setTicked] = useState<Map<CategoryId, Status>>(new Map());
  const [report, setReport] = useState<ScanReport | null>(null);
  const [previous, setPrevious] = useState<HistoryEntry | null>(null);
  const [intel, setIntel] = useState<IntelState>({});
  const [intelDone, setIntelDone] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const inputRef = useRef<HTMLInputElement>(null);
  const abortRef = useRef<AbortController | null>(null);
  const autoStarted = useRef(false);

  const scan = useCallback(async (raw: string) => {
    const value = raw.trim();
    if (!value) {
      setError("Enter a domain name, e.g. example.com.");
      setPhase("error");
      return;
    }
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    setPhase("scanning");
    setError(null);
    setReport(null);
    setIntel({});
    setIntelDone(false);
    setTicked(new Map());
    setScanningDomain(value.replace(/^[a-z]+:\/\//i, "").split(/[/?#]/)[0]);

    // Events arrive in bursts; release ticks at a steady pace for a readable animation.
    const queue: Array<{ id: CategoryId; status: Status }> = [];
    let streamDone = false;
    const pump = new Promise<void>((resolve) => {
      const timer = setInterval(() => {
        if (controller.signal.aborted) {
          clearInterval(timer);
          return resolve();
        }
        const next = queue.shift();
        if (next) {
          setTicked((prev) => new Map(prev).set(next.id, next.status));
        } else if (streamDone) {
          clearInterval(timer);
          resolve();
        }
      }, TICK_MS);
    });

    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: value }),
        signal: controller.signal,
      });
      if (!res.ok || !res.body) {
        const data = (await res.json().catch(() => null)) as { error?: string } | null;
        throw new Error(data?.error ?? `Scan failed (HTTP ${res.status}).`);
      }

      const body = res.body;
      let resolveResult!: (r: ScanReport) => void;
      let rejectResult!: (e: Error) => void;
      const resultPromise = new Promise<ScanReport>((resolve, reject) => {
        resolveResult = resolve;
        rejectResult = reject;
      });
      // Keep reading after the result arrives: Hacker's View sources stream in afterwards.
      void (async () => {
        const reader = body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";
        let gotResult = false;
        try {
          for (;;) {
            const { value: chunk, done } = await reader.read();
            if (done) break;
            buffer += decoder.decode(chunk, { stream: true });
            let nl;
            while ((nl = buffer.indexOf("\n")) !== -1) {
              const line = buffer.slice(0, nl).trim();
              buffer = buffer.slice(nl + 1);
              if (!line) continue;
              const event = JSON.parse(line) as ScanEvent;
              if (event.type === "start") setScanningDomain(event.domain);
              else if (event.type === "check") queue.push({ id: event.id, status: event.status });
              else if (event.type === "result") {
                gotResult = true;
                resolveResult(event.report);
              } else if (event.type === "intel") {
                if (!controller.signal.aborted) setIntel((prev) => ({ ...prev, [event.source]: event.data }));
              } else if (event.type === "error") rejectResult(new Error(event.message));
            }
          }
          if (!gotResult) rejectResult(new Error("The scan ended unexpectedly. Please try again."));
        } catch (e) {
          rejectResult(e instanceof Error ? e : new Error("Network error"));
        } finally {
          if (!controller.signal.aborted) setIntelDone(true);
        }
      })();

      const finalReport = await resultPromise;
      streamDone = true;
      await pump;
      if (controller.signal.aborted) return;
      await new Promise((r) => setTimeout(r, 350));
      if (controller.signal.aborted) return;

      const done: ScanReport = finalReport;
      setPrevious(recordScan({ domain: done.domain, grade: done.grade, score: done.score, date: done.scannedAt }));
      setReport(done);
      setPhase("done");
      // Make the result shareable: /?domain=example.com
      window.history.replaceState(null, "", `/?domain=${encodeURIComponent(done.domain)}`);
      requestAnimationFrame(() =>
        document.getElementById("results")?.scrollIntoView({ behavior: "smooth", block: "start" }),
      );
    } catch (e) {
      streamDone = true;
      if (controller.signal.aborted) return;
      controller.abort(); // stop the tick pump
      setError(
        e instanceof Error && e.message !== "Failed to fetch"
          ? e.message
          : "Network error. Check your connection and try again.",
      );
      setPhase("error");
    }
  }, []);

  // Auto-run a scan for shared links like /?domain=example.com
  useEffect(() => {
    if (autoStarted.current || !initialDomain) return;
    autoStarted.current = true;
    void scan(initialDomain);
  }, [initialDomain, scan]);

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (phase === "scanning") return;
    void scan(input);
  }

  function reset() {
    abortRef.current?.abort();
    setPhase("idle");
    setReport(null);
    setError(null);
    setInput("");
    window.history.replaceState(null, "", "/");
    window.scrollTo({ top: 0, behavior: "smooth" });
    setTimeout(() => inputRef.current?.focus(), 300);
  }

  const busy = phase === "scanning";

  return (
    <>
      <form onSubmit={onSubmit} className="mx-auto mt-10 w-full max-w-2xl" noValidate>
        <label htmlFor="domain" className="sr-only">
          Website domain
        </label>
        <div className="group flex flex-col gap-2 rounded-2xl border border-white/10 bg-ink-900/80 p-2 shadow-2xl shadow-indigo-950/40 ring-indigo-400/40 backdrop-blur transition focus-within:border-indigo-400/50 focus-within:ring-4 sm:flex-row sm:items-center">
          <div className="flex flex-1 items-center gap-3 px-3">
            <GlobeIcon className="size-5 shrink-0 text-slate-500 transition group-focus-within:text-indigo-300" />
            <input
              ref={inputRef}
              id="domain"
              name="domain"
              type="text"
              inputMode="url"
              autoComplete="off"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              maxLength={253}
              placeholder="example.com"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              disabled={busy}
              aria-invalid={phase === "error"}
              aria-describedby={error ? "scan-error" : undefined}
              className="h-12 w-full min-w-0 bg-transparent text-base text-white placeholder:text-slate-500 focus:outline-none disabled:opacity-60 sm:text-lg"
            />
          </div>
          <button
            type="submit"
            disabled={busy}
            className="inline-flex h-12 items-center justify-center gap-2 rounded-xl bg-indigo-500 px-6 text-base font-semibold text-white shadow-lg shadow-indigo-500/25 transition hover:bg-indigo-400 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-indigo-300 disabled:cursor-wait disabled:opacity-70"
          >
            {busy ? (
              <>
                <SpinnerIcon className="size-5 animate-spin" />
                Scanning
              </>
            ) : (
              <>
                Scan
                <ArrowRightIcon className="size-5" />
              </>
            )}
          </button>
        </div>
        {phase === "error" && error && (
          <p
            id="scan-error"
            role="alert"
            className="mt-4 flex animate-fade-up items-start gap-2.5 rounded-xl bg-rose-500/10 px-4 py-3 text-sm text-rose-200 ring-1 ring-rose-400/25"
          >
            <AlertIcon className="mt-0.5 size-4 shrink-0" />
            <span className="break-words">{error}</span>
          </p>
        )}
        <p className="mt-3 text-center text-xs text-slate-500">
          Passive checks only: response headers, TLS handshakes, DNS records, security.txt and robots.txt.
        </p>
      </form>

      {phase !== "scanning" && phase !== "done" && (
        <RecentScans
          disabled={busy}
          onSelect={(d) => {
            setInput(d);
            void scan(d);
          }}
        />
      )}

      <div id="results" className="scroll-mt-20">
        {phase === "scanning" && (
          <div className="mt-12">
            <ScanProgress domain={scanningDomain} ticked={ticked} />
          </div>
        )}
        {phase === "done" && report && (
          <div className="mt-12">
            <Report report={report} previous={previous} intel={intel} intelDone={intelDone} onReset={reset} />
          </div>
        )}
      </div>
    </>
  );
}
