import Link from "next/link";
import { site } from "@/lib/site";

export function SiteFooter() {
  return (
    <footer className="border-t border-white/[0.06]">
      <div className="mx-auto flex max-w-6xl flex-col gap-3 px-4 py-8 text-sm text-slate-500 sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <p>
          {site.name} · Built by {site.author}. Scans only read public information.
        </p>
        <nav aria-label="Footer" className="flex gap-5">
          <Link href="/" className="transition hover:text-slate-300">
            Scanner
          </Link>
          <Link href="/about" className="transition hover:text-slate-300">
            About &amp; methodology
          </Link>
        </nav>
      </div>
    </footer>
  );
}
