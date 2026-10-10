import type { RobotsDetails, Technology, TlsDetails } from "@/lib/scanner/types";

const PROTOCOL_STYLE = {
  supported: "bg-emerald-400/10 text-emerald-200 ring-emerald-400/25",
  rejected: "bg-white/[0.04] text-slate-400 ring-white/[0.08]",
  unknown: "bg-white/[0.04] text-slate-500 ring-white/[0.08]",
} as const;
const LEGACY_SUPPORTED = "bg-rose-500/10 text-rose-200 ring-rose-400/25";

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-0.5 sm:grid-cols-[9rem_1fr] sm:gap-3">
      <dt className="text-xs font-medium uppercase tracking-wider text-slate-500 sm:pt-0.5">{label}</dt>
      <dd className="min-w-0 break-words text-sm text-slate-200">{children}</dd>
    </div>
  );
}

/** Protocol support grid, cipher, key, chain and SANs. All values are rendered as text. */
export function TlsDetailsPanel({ tls }: { tls: TlsDetails }) {
  return (
    <div className="mx-2 mt-4 space-y-5 rounded-2xl bg-ink-950/60 p-4 ring-1 ring-white/[0.06] sm:mx-3 sm:p-5">
      <div>
        <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500">Protocol versions accepted</h4>
        <ul className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
          {tls.protocols.map((p) => {
            const legacy = p.version === "TLS 1.0" || p.version === "TLS 1.1";
            const style = legacy && p.result === "supported" ? LEGACY_SUPPORTED : PROTOCOL_STYLE[p.result];
            return (
              <li key={p.version} className={`rounded-xl px-3 py-2 text-sm ring-1 ${style}`}>
                <span className="block font-semibold">{p.version}</span>
                <span className="text-xs opacity-80">
                  {p.result === "supported"
                    ? legacy
                      ? "Accepted (outdated)"
                      : "Accepted"
                    : p.result === "rejected"
                      ? "Refused"
                      : "Couldn't test"}
                </span>
              </li>
            );
          })}
        </ul>
      </div>

      <dl className="space-y-2.5">
        {tls.negotiated && <Row label="Negotiated">{tls.negotiated.replace("TLSv", "TLS ")}</Row>}
        {tls.cipher && (
          <Row label="Cipher">
            <span className="font-mono text-[13px]">{tls.cipher}</span>
          </Row>
        )}
        {tls.keyExchange && <Row label="Key exchange">{tls.keyExchange}</Row>}
        {tls.key && (
          <Row label="Certificate key">
            {tls.key.type}
            {tls.key.bits ? ` ${tls.key.bits}-bit` : ""}
          </Row>
        )}
        {tls.signatureAlgorithm && <Row label="Signature">{tls.signatureAlgorithm}</Row>}
      </dl>

      {tls.chain.length > 0 && (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500">Certificate chain</h4>
          <ol className="mt-2 space-y-2">
            {tls.chain.map((c, i) => (
              <li key={`${c.subject}-${i}`} className="flex gap-3">
                <span className="mt-1 flex flex-col items-center" aria-hidden="true">
                  <span className={`size-2.5 rounded-full ${i === 0 ? "bg-indigo-300" : "bg-slate-500"}`} />
                  {i < tls.chain.length - 1 && <span className="mt-1 h-full w-px bg-white/10" />}
                </span>
                <div className="min-w-0 pb-1">
                  <p className="break-words text-sm text-slate-100">
                    {c.subject}{" "}
                    <span className="rounded bg-white/[0.06] px-1.5 py-0.5 text-[11px] uppercase tracking-wide text-slate-400">
                      {c.role}
                    </span>
                  </p>
                  <p className="break-words text-xs text-slate-500">
                    Issued by {c.issuer} · {c.key} · {c.signatureAlgorithm}
                  </p>
                </div>
              </li>
            ))}
          </ol>
        </div>
      )}

      {tls.sanTotal > 0 && (
        <div>
          <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
            Names on this certificate ({tls.sanTotal})
          </h4>
          <ul className="mt-2 flex flex-wrap gap-1.5">
            {tls.sans.map((n) => (
              <li
                key={n}
                className="max-w-full truncate rounded-md bg-white/[0.04] px-2 py-0.5 font-mono text-xs text-slate-300 ring-1 ring-white/[0.06]"
              >
                {n}
              </li>
            ))}
            {tls.sanTotal > tls.sans.length && (
              <li className="px-1 py-0.5 text-xs text-slate-500">and {tls.sanTotal - tls.sans.length} more</li>
            )}
          </ul>
        </div>
      )}
    </div>
  );
}

export function TechnologyList({ technologies }: { technologies: Technology[] }) {
  if (!technologies.length) return null;
  return (
    <div className="mx-2 mt-4 rounded-2xl bg-ink-950/60 p-4 ring-1 ring-white/[0.06] sm:mx-3 sm:p-5">
      <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500">Detected technologies</h4>
      <ul className="mt-2.5 flex flex-wrap gap-2">
        {technologies.map((t) => (
          <li
            key={t.name}
            title={`Detected from ${t.source}`}
            className={`rounded-lg px-2.5 py-1 text-sm ring-1 ${
              t.version
                ? "bg-amber-400/10 text-amber-100 ring-amber-400/25"
                : "bg-white/[0.04] text-slate-200 ring-white/[0.08]"
            }`}
          >
            {t.name}
            {t.version && <span className="ml-1.5 font-mono text-xs text-amber-300">v{t.version}</span>}
            <span className="ml-1.5 text-xs text-slate-500">{t.category}</span>
          </li>
        ))}
      </ul>
      {technologies.some((t) => t.version) && (
        <p className="mt-2.5 text-xs text-amber-200/80">Highlighted entries expose an exact version number.</p>
      )}
    </div>
  );
}

export function RobotsList({ robots }: { robots: RobotsDetails }) {
  if (!robots.found || robots.total === 0) return null;
  const sensitive = new Set(robots.sensitive);
  return (
    <div className="mx-2 mt-4 rounded-2xl bg-ink-950/60 p-4 ring-1 ring-white/[0.06] sm:mx-3 sm:p-5">
      <h4 className="text-xs font-semibold uppercase tracking-wider text-slate-500">
        robots.txt Disallow rules ({robots.total})
      </h4>
      <ul className="mt-2.5 flex max-h-56 flex-wrap gap-1.5 overflow-auto">
        {robots.disallow.map((p) => (
          <li
            key={p}
            className={`max-w-full truncate rounded-md px-2 py-0.5 font-mono text-xs ring-1 ${
              sensitive.has(p)
                ? "bg-rose-500/10 text-rose-200 ring-rose-400/25"
                : "bg-white/[0.04] text-slate-400 ring-white/[0.06]"
            }`}
          >
            {p}
          </li>
        ))}
        {robots.total > robots.disallow.length && (
          <li className="px-1 py-0.5 text-xs text-slate-500">and {robots.total - robots.disallow.length} more</li>
        )}
      </ul>
      <p className="mt-2.5 text-xs text-slate-500">
        Listed for information only. The scanner never requests these paths.
      </p>
    </div>
  );
}
