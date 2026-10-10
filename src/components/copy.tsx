"use client";

import { useEffect, useRef, useState } from "react";
import { CheckIcon, CopyIcon } from "@/components/icons";

export async function copyText(text: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Fallback for browsers/contexts without the async clipboard API.
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.className = "fixed -left-[9999px]";
    document.body.appendChild(ta);
    ta.select();
    document.execCommand("copy");
    ta.remove();
  }
}

export function CopyButton({
  text,
  label = "Copy",
  className = "",
}: {
  text: string | (() => string);
  label?: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );
  async function onClick() {
    await copyText(typeof text === "function" ? text() : text);
    setCopied(true);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setCopied(false), 2000);
  }
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center justify-center gap-2 transition focus-visible:outline-2 focus-visible:outline-indigo-400 ${className}`}
    >
      {copied ? <CheckIcon className="size-4 text-emerald-300" /> : <CopyIcon className="size-4" />}
      <span aria-live="polite">{copied ? "Copied!" : label}</span>
    </button>
  );
}
