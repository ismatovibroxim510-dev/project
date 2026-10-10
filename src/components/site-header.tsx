import Link from "next/link";
import { ShieldIcon } from "@/components/icons";
import { site } from "@/lib/site";

export function SiteHeader() {
  return (
    <header className="sticky top-0 z-40 border-b border-white/[0.06] bg-ink-950/75 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between px-4 sm:px-6">
        <Link
          href="/"
          className="group flex items-center gap-2.5 rounded-lg focus-visible:outline-2 focus-visible:outline-indigo-400"
        >
          <span className="grid size-8 place-items-center rounded-lg bg-gradient-to-br from-indigo-500/25 to-cyan-400/20 ring-1 ring-white/10 transition group-hover:ring-indigo-400/50">
            <ShieldIcon className="size-[18px] text-indigo-300" />
          </span>
          <span className="text-[15px] font-semibold tracking-tight text-white">{site.name}</span>
        </Link>
        <nav aria-label="Main" className="flex items-center gap-1 text-sm">
          <Link href="/" className="rounded-lg px-3 py-2 text-slate-300 transition hover:bg-white/5 hover:text-white">
            Scan
          </Link>
          <Link
            href="/about"
            className="rounded-lg px-3 py-2 text-slate-300 transition hover:bg-white/5 hover:text-white"
          >
            About
          </Link>
        </nav>
      </div>
    </header>
  );
}
