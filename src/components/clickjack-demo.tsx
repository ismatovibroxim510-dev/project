"use client";

import { useEffect, useState } from "react";
import { TargetIcon } from "@/components/icons";

const LOAD_TIMEOUT_MS = 12000;

/** Illustrated fallback: shows the two layers of a clickjacking page without loading the real site. */
function Illustration({ host }: { host: string }) {
  return (
    <div className="relative grid gap-4 rounded-2xl bg-ink-950/80 p-5 ring-1 ring-white/[0.08] sm:grid-cols-[1fr_auto_1fr] sm:items-center">
      <div className="rounded-xl bg-white/[0.04] p-4 ring-1 ring-white/[0.08]">
        <p className="text-xs font-semibold uppercase tracking-wider text-rose-300">What the victim sees</p>
        <div className="mt-3 rounded-lg bg-gradient-to-br from-fuchsia-500/30 to-amber-400/20 p-4 text-center">
          <p className="text-sm font-semibold text-white">🎉 You&apos;ve been selected!</p>
          <div className="mx-auto mt-3 w-fit rounded-lg bg-amber-400 px-4 py-2 text-sm font-bold text-ink-950">
            Click here to win!
          </div>
        </div>
      </div>
      <div className="text-center text-xs text-slate-400" aria-hidden="true">
        <span className="hidden sm:inline">+ invisible layer →</span>
        <span className="sm:hidden">+ invisible layer ↓</span>
      </div>
      <div className="rounded-xl border border-dashed border-rose-400/40 bg-white/[0.02] p-4">
        <p className="text-xs font-semibold uppercase tracking-wider text-rose-300">Hidden on top (opacity 0)</p>
        <div className="mt-3 rounded-lg bg-white/[0.06] p-4 text-center">
          <p className="truncate text-sm text-slate-300">{host}</p>
          <div className="mx-auto mt-3 w-fit rounded-lg bg-rose-500/80 px-4 py-2 text-sm font-semibold text-white">
            Delete account
          </div>
        </div>
      </div>
      <p className="text-sm text-slate-400 sm:col-span-3">
        The victim aims for &ldquo;Click here to win!&rdquo;, but the click lands on the invisible page stacked on top,
        while they&apos;re logged in to {host}.
      </p>
    </div>
  );
}

export function ClickjackDemo({ host, url }: { host: string; url: string | null }) {
  const [state, setState] = useState<"loading" | "loaded" | "fallback">(url ? "loading" : "fallback");
  const [victimView, setVictimView] = useState(false);

  useEffect(() => {
    if (!url || state !== "loading") return;
    const t = setTimeout(() => setState("fallback"), LOAD_TIMEOUT_MS);
    return () => clearTimeout(t);
  }, [url, state]);

  const src = url ? `/frame-demo?url=${encodeURIComponent(url)}` : null;

  return (
    <section
      aria-labelledby="clickjack-title"
      className="animate-fade-up rounded-3xl border border-rose-400/20 bg-gradient-to-b from-rose-500/[0.06] to-ink-900/60 p-5 sm:p-7"
    >
      <div className="flex items-start gap-4">
        <span className="grid size-11 shrink-0 place-items-center rounded-2xl bg-rose-500/15 ring-1 ring-rose-400/25">
          <TargetIcon className="size-5 text-rose-200" />
        </span>
        <div className="min-w-0">
          <h3 id="clickjack-title" className="text-lg font-semibold text-white">
            See the risk: clickjacking
          </h3>
          <p className="mt-1 text-sm leading-relaxed text-slate-400">
            {host} doesn&apos;t tell browsers to refuse being embedded in other sites (no X-Frame-Options or CSP
            frame-ancestors), so any website can load it inside an invisible frame.
          </p>
        </div>
      </div>

      <div className="mt-5">
        {state !== "fallback" && src ? (
          <>
            <div className="relative h-[22rem] overflow-hidden rounded-2xl bg-white ring-1 ring-white/10 sm:h-[26rem]">
              {/* The real site, sandboxed (no scripts/forms/navigation) and non-interactive. */}
              <iframe
                src={src}
                title={`${host} embedded in a frame (demonstration)`}
                sandbox=""
                referrerPolicy="no-referrer"
                tabIndex={-1}
                onLoad={() => setState("loaded")}
                className={`pointer-events-none absolute inset-0 h-full w-full border-0 transition-opacity duration-500 ${victimView ? "opacity-[0.03]" : "opacity-100"}`}
              />
              {/* Decorative bait. It is a plain div: not a button, not focusable, ignores clicks. */}
              <div aria-hidden="true" className="pointer-events-none absolute inset-0 grid place-items-center p-6">
                <div
                  className={`rounded-2xl p-6 text-center shadow-2xl transition-all duration-500 ${
                    victimView
                      ? "bg-gradient-to-br from-fuchsia-600 to-amber-500 opacity-100"
                      : "bg-gradient-to-br from-fuchsia-600/55 to-amber-500/55 opacity-90 outline-2 outline-dashed outline-white/70 backdrop-blur-[1px]"
                  }`}
                >
                  <p className="text-base font-semibold text-white drop-shadow">🎉 Congratulations!</p>
                  <div className="mt-3 rounded-xl bg-amber-300 px-6 py-3 text-lg font-extrabold text-ink-950">
                    Click here to win!
                  </div>
                  <p className="mt-2 text-xs font-medium text-white/90">Fake overlay · demonstration only</p>
                </div>
              </div>
              {state === "loading" && (
                <div className="absolute inset-x-0 bottom-0 bg-ink-950/80 px-4 py-2 text-xs text-slate-300">
                  Loading {host} in a sandboxed frame…
                </div>
              )}
            </div>
            <div className="mt-3 flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
              <div
                className="inline-flex w-fit rounded-xl bg-white/[0.04] p-1 ring-1 ring-white/[0.08]"
                role="group"
                aria-label="Demo view"
              >
                <button
                  type="button"
                  aria-pressed={!victimView}
                  onClick={() => setVictimView(false)}
                  className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${!victimView ? "bg-white/10 text-white" : "text-slate-400 hover:text-slate-200"}`}
                >
                  Attacker&apos;s view
                </button>
                <button
                  type="button"
                  aria-pressed={victimView}
                  onClick={() => setVictimView(true)}
                  className={`rounded-lg px-3 py-1.5 text-xs font-medium transition ${victimView ? "bg-white/10 text-white" : "text-slate-400 hover:text-slate-200"}`}
                >
                  Victim&apos;s view
                </button>
              </div>
              <button
                type="button"
                onClick={() => setState("fallback")}
                className="w-fit text-xs text-slate-400 underline decoration-white/20 underline-offset-4 hover:text-slate-200"
              >
                Site looks blank? Show the illustration instead
              </button>
            </div>
            <p className="mt-2 text-xs text-slate-500">
              The preview runs with scripts disabled for safety, so some sites look blank or unstyled. Nothing in it is
              clickable.
            </p>
          </>
        ) : (
          <Illustration host={host} />
        )}
      </div>

      <div className="mt-6 grid gap-4 text-sm leading-relaxed sm:grid-cols-3">
        <div>
          <h4 className="font-semibold text-white">What is clickjacking?</h4>
          <p className="mt-1 text-slate-300">
            An attacker&apos;s page loads your site in a transparent frame and places bait (&ldquo;Click here to
            win!&rdquo;) exactly underneath a real button. The visitor thinks they&apos;re clicking the bait;
            they&apos;re really clicking your site.
          </p>
        </div>
        <div>
          <h4 className="font-semibold text-white">Why it matters</h4>
          <p className="mt-1 text-slate-300">
            The click happens with the visitor&apos;s own login, so it can change settings, make purchases, delete data
            or grant permissions, without them noticing.
          </p>
        </div>
        <div>
          <h4 className="font-semibold text-white">How the fix works</h4>
          <p className="mt-1 text-slate-300">
            With{" "}
            <code className="rounded bg-white/[0.07] px-1 font-mono text-[0.85em]">X-Frame-Options: SAMEORIGIN</code> or{" "}
            <code className="rounded bg-white/[0.07] px-1 font-mono text-[0.85em]">
              frame-ancestors &apos;self&apos;
            </code>
            , browsers refuse to render the site inside other sites&apos; frames, so this demo would show an empty box.
          </p>
        </div>
      </div>
    </section>
  );
}
