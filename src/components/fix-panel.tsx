"use client";

import { createContext, useContext, useId, useState, type KeyboardEvent, type ReactNode } from "react";
import { CopyButton } from "@/components/copy";
import { AlertIcon, WrenchIcon } from "@/components/icons";
import { RichText } from "@/components/ui";
import { PLATFORMS, type FindingFix, type FixBundle, type Platform, type PlatformFix, type Snippet } from "@/lib/fixes";

const PREF_KEY = "sitegrade:platform";

function readPreferredPlatform(): Platform {
  try {
    const v = localStorage.getItem(PREF_KEY);
    if (v && PLATFORMS.some((p) => p.id === v)) return v as Platform;
  } catch {
    // Storage blocked; fall back to the default.
  }
  return "nginx";
}

/** One platform choice shared by every fix panel in the report. */
const PlatformContext = createContext<{ platform: Platform; setPlatform: (p: Platform) => void }>({
  platform: "nginx",
  setPlatform: () => {},
});

export function PlatformProvider({ children }: { children: ReactNode }) {
  // The report only ever renders in the browser (after a scan), so reading storage here is safe.
  const [platform, setState] = useState<Platform>(readPreferredPlatform);
  const setPlatform = (p: Platform) => {
    setState(p);
    try {
      localStorage.setItem(PREF_KEY, p);
    } catch {}
  };
  return <PlatformContext.Provider value={{ platform, setPlatform }}>{children}</PlatformContext.Provider>;
}

export function CodeBlock({ snippet }: { snippet: Snippet }) {
  return (
    <div className="overflow-hidden rounded-xl bg-ink-950 ring-1 ring-white/[0.08]">
      <div className="flex items-center justify-between gap-3 border-b border-white/[0.06] px-3.5 py-2">
        <span className="min-w-0 truncate font-mono text-xs text-slate-400">{snippet.filename}</span>
        <CopyButton
          text={snippet.code}
          className="shrink-0 rounded-md px-2 py-1 text-xs font-medium text-slate-300 hover:bg-white/[0.06] hover:text-white"
        />
      </div>
      {/* Generated config is shown as text only. */}
      <pre className="max-h-[26rem] overflow-auto p-3.5 font-mono text-[12.5px] leading-relaxed text-slate-200">
        <code>{snippet.code}</code>
      </pre>
    </div>
  );
}

function Tabs<T extends string>({
  tabs,
  value,
  onChange,
  label,
  idBase,
}: {
  tabs: Array<{ id: T; label: string }>;
  value: T;
  onChange: (v: T) => void;
  label: string;
  idBase: string;
}) {
  function onKeyDown(e: KeyboardEvent<HTMLButtonElement>, i: number) {
    if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
    e.preventDefault();
    const next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
    onChange(next.id);
    document.getElementById(`${idBase}-tab-${next.id}`)?.focus();
  }
  return (
    <div role="tablist" aria-label={label} className="-mx-1 flex gap-1 overflow-x-auto px-1 pb-1">
      {tabs.map((t, i) => {
        const selected = t.id === value;
        return (
          <button
            key={t.id}
            id={`${idBase}-tab-${t.id}`}
            type="button"
            role="tab"
            aria-selected={selected}
            aria-controls={`${idBase}-panel`}
            tabIndex={selected ? 0 : -1}
            onClick={() => onChange(t.id)}
            onKeyDown={(e) => onKeyDown(e, i)}
            className={`shrink-0 rounded-lg px-3 py-1.5 text-xs font-medium transition focus-visible:outline-2 focus-visible:outline-indigo-400 ${
              selected
                ? "bg-indigo-500 text-white"
                : "bg-white/[0.04] text-slate-300 ring-1 ring-white/[0.07] hover:bg-white/[0.08]"
            }`}
          >
            {t.label}
          </button>
        );
      })}
    </div>
  );
}

function Warning({ text }: { text: string }) {
  return (
    <p className="flex gap-2.5 rounded-xl bg-amber-400/10 px-3.5 py-3 text-sm leading-relaxed text-amber-100 ring-1 ring-amber-400/25">
      <AlertIcon className="mt-0.5 size-4 shrink-0 text-amber-300" />
      <span>{text}</span>
    </p>
  );
}

function PlatformBody({ fix }: { fix: PlatformFix }) {
  if (!fix.snippets.length && !fix.notes.length) {
    return <p className="text-sm text-slate-400">Nothing to change for this platform.</p>;
  }
  return (
    <div className="space-y-3">
      {fix.snippets.map((s) => (
        <CodeBlock key={s.filename + s.code.length} snippet={s} />
      ))}
      {fix.notes.length > 0 && (
        <ul className="space-y-1.5 text-sm leading-relaxed text-slate-300">
          {fix.notes.map((n) => (
            <li key={n} className="flex gap-2">
              <span aria-hidden="true" className="mt-2 size-1 shrink-0 rounded-full bg-indigo-300" />
              <span>
                <RichText text={n} />
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Copy-paste config for one finding. */
export function FixPanel({ fix }: { fix: FindingFix }) {
  const { platform, setPlatform } = useContext(PlatformContext);
  const idBase = useId();
  if (fix.kind === "generic") {
    return (
      <div className="space-y-3">
        {fix.warning && <Warning text={fix.warning} />}
        {fix.snippets.map((s) => (
          <CodeBlock key={s.filename + s.code.length} snippet={s} />
        ))}
        {fix.notes.map((n) => (
          <p key={n} className="text-sm leading-relaxed text-slate-300">
            <RichText text={n} />
          </p>
        ))}
      </div>
    );
  }
  return (
    <div className="space-y-3">
      {fix.warning && <Warning text={fix.warning} />}
      <Tabs tabs={PLATFORMS} value={platform} onChange={setPlatform} label="Platform" idBase={idBase} />
      <div id={`${idBase}-panel`} role="tabpanel" aria-labelledby={`${idBase}-tab-${platform}`}>
        <PlatformBody fix={fix.byPlatform[platform]} />
      </div>
    </div>
  );
}

type AllTab = Platform | "dns";

/** Every fix merged into one config per platform, plus all DNS records. */
export function AllFixes({ bundle }: { bundle: FixBundle }) {
  const { platform, setPlatform } = useContext(PlatformContext);
  const [dnsSelected, setDnsSelected] = useState(false);
  const idBase = useId();
  const hasDns = bundle.dns.snippets.length > 0;
  const hasServer = PLATFORMS.some((p) => bundle.combined[p.id].snippets.length || bundle.combined[p.id].notes.length);
  const tabs: Array<{ id: AllTab; label: string }> = [
    ...(hasServer ? PLATFORMS : []),
    ...(hasDns ? [{ id: "dns" as const, label: "DNS records" }] : []),
  ];
  const value: AllTab = (dnsSelected && hasDns) || !hasServer ? "dns" : platform;
  const onChange = (v: AllTab) => {
    if (v === "dns") setDnsSelected(true);
    else {
      setDnsSelected(false);
      setPlatform(v);
    }
  };
  if (!bundle.hasAny) return null;

  return (
    <section
      aria-labelledby="all-fixes-title"
      className="animate-fade-up rounded-3xl border border-indigo-400/20 bg-gradient-to-b from-indigo-500/[0.07] to-ink-900/60 p-5 sm:p-7"
    >
      <div className="flex items-start gap-4">
        <span className="grid size-11 shrink-0 place-items-center rounded-2xl bg-indigo-500/15 ring-1 ring-indigo-400/25">
          <WrenchIcon className="size-5 text-indigo-200" />
        </span>
        <div className="min-w-0">
          <h3 id="all-fixes-title" className="text-lg font-semibold text-white">
            All fixes
          </h3>
          <p className="mt-1 text-sm text-slate-400">
            Every change this scan recommends, combined into one config for your platform. Each issue below also has its
            own snippet.
          </p>
        </div>
      </div>
      <div className="mt-5 space-y-3">
        <Tabs tabs={tabs} value={value} onChange={onChange} label="Platform for all fixes" idBase={idBase} />
        {value !== "dns" && bundle.combinedWarning && <Warning text={bundle.combinedWarning} />}
        <div id={`${idBase}-panel`} role="tabpanel" aria-labelledby={`${idBase}-tab-${value}`}>
          {value === "dns" ? <PlatformBody fix={bundle.dns} /> : <PlatformBody fix={bundle.combined[value]} />}
        </div>
      </div>
    </section>
  );
}
