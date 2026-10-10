import type { ComponentType, ReactNode, SVGProps } from "react";
import {
  AlertIcon,
  CertificateIcon,
  CheckIcon,
  CookieIcon,
  DnsIcon,
  FileTextIcon,
  EyeOffIcon,
  HeadersIcon,
  InfoIcon,
  LockIcon,
  MailIcon,
  XIcon,
} from "@/components/icons";
import type { CategoryId, Grade, Status } from "@/lib/scanner/types";

export const CATEGORY_ICONS: Record<CategoryId, ComponentType<SVGProps<SVGSVGElement>>> = {
  https: LockIcon,
  tls: CertificateIcon,
  headers: HeadersIcon,
  leakage: EyeOffIcon,
  email: MailIcon,
  cookies: CookieIcon,
  dns: DnsIcon,
  files: FileTextIcon,
};

export const STATUS_STYLES: Record<Status, { label: string; text: string; bg: string; ring: string; bar: string }> = {
  pass: {
    label: "Pass",
    text: "text-emerald-300",
    bg: "bg-emerald-400/10",
    ring: "ring-emerald-400/25",
    bar: "bg-emerald-400",
  },
  warn: {
    label: "Warning",
    text: "text-amber-300",
    bg: "bg-amber-400/10",
    ring: "ring-amber-400/25",
    bar: "bg-amber-400",
  },
  fail: { label: "Fail", text: "text-rose-300", bg: "bg-rose-500/10", ring: "ring-rose-400/25", bar: "bg-rose-400" },
  info: { label: "Info", text: "text-sky-300", bg: "bg-sky-400/10", ring: "ring-sky-400/25", bar: "bg-sky-400" },
};

export const GRADE_STYLES: Record<Grade, { text: string; stroke: string; glow: string }> = {
  "A+": { text: "text-emerald-300", stroke: "stroke-emerald-400", glow: "shadow-emerald-500/20" },
  A: { text: "text-emerald-300", stroke: "stroke-emerald-400", glow: "shadow-emerald-500/20" },
  B: { text: "text-lime-300", stroke: "stroke-lime-400", glow: "shadow-lime-500/20" },
  C: { text: "text-amber-300", stroke: "stroke-amber-400", glow: "shadow-amber-500/20" },
  D: { text: "text-orange-300", stroke: "stroke-orange-400", glow: "shadow-orange-500/20" },
  F: { text: "text-rose-300", stroke: "stroke-rose-400", glow: "shadow-rose-500/20" },
};

export function StatusIcon({ status, className = "size-4" }: { status: Status; className?: string }) {
  const Icon = status === "pass" ? CheckIcon : status === "warn" ? AlertIcon : status === "fail" ? XIcon : InfoIcon;
  const s = STATUS_STYLES[status];
  return (
    <span className={`grid shrink-0 place-items-center rounded-full ${s.bg} ${s.text} ring-1 ${s.ring} p-1`}>
      <Icon className={className} strokeWidth={2.4} />
    </span>
  );
}

export function StatusBadge({ status }: { status: Status }) {
  const s = STATUS_STYLES[status];
  return (
    <span
      className={`inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ring-1 ${s.bg} ${s.text} ${s.ring}`}
    >
      {s.label}
    </span>
  );
}

/**
 * Renders text with `backtick` spans as <code>. Everything stays a React text
 * node, so scanned content can never be interpreted as HTML.
 */
export function RichText({ text }: { text: string }): ReactNode {
  const parts = text.split(/`([^`]+)`/g);
  return parts.map((part, i) =>
    i % 2 === 1 ? (
      <code
        key={i}
        className="rounded bg-white/[0.07] px-1.5 py-0.5 font-mono text-[0.85em] text-indigo-200 break-words"
      >
        {part}
      </code>
    ) : (
      part
    ),
  );
}
