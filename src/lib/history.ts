import { useSyncExternalStore } from "react";
import type { Grade } from "@/lib/scanner/types";

/**
 * Recent scans, kept only in this browser's localStorage. Every storage access
 * is wrapped in try/catch so the app works when storage is blocked or full.
 */

export interface HistoryEntry {
  domain: string;
  grade: Grade;
  score: number;
  date: string;
}

export const HISTORY_KEY = "sitegrade:history";
export const HISTORY_MAX = 20;
const GRADES: Grade[] = ["A+", "A", "B", "C", "D", "F"];
const EMPTY: HistoryEntry[] = [];

function isEntry(v: unknown): v is HistoryEntry {
  if (!v || typeof v !== "object") return false;
  const e = v as Record<string, unknown>;
  return (
    typeof e.domain === "string" &&
    e.domain.length <= 253 &&
    /^[a-z0-9.-]+$/.test(e.domain) &&
    GRADES.includes(e.grade as Grade) &&
    typeof e.score === "number" &&
    e.score >= 0 &&
    e.score <= 100 &&
    typeof e.date === "string" &&
    !Number.isNaN(Date.parse(e.date))
  );
}

/** Parse stored JSON, dropping anything malformed (storage is user-editable). */
export function parseHistory(raw: string | null): HistoryEntry[] {
  if (!raw) return EMPTY;
  try {
    const data: unknown = JSON.parse(raw);
    return Array.isArray(data) ? data.filter(isEntry).slice(0, HISTORY_MAX) : EMPTY;
  } catch {
    return EMPTY;
  }
}

/** Add a scan (newest first) and return the previous scan of the same domain, if any. */
export function withScan(
  list: HistoryEntry[],
  entry: HistoryEntry,
): { list: HistoryEntry[]; previous: HistoryEntry | null } {
  const previous = list.find((e) => e.domain === entry.domain) ?? null;
  return { list: [entry, ...list].slice(0, HISTORY_MAX), previous };
}

export type Trend = "up" | "down" | "same";

export function compareScans(
  previous: Pick<HistoryEntry, "grade" | "score">,
  current: Pick<HistoryEntry, "grade" | "score">,
): Trend {
  const byGrade = GRADES.indexOf(previous.grade) - GRADES.indexOf(current.grade);
  if (byGrade > 0) return "up";
  if (byGrade < 0) return "down";
  return current.score > previous.score ? "up" : current.score < previous.score ? "down" : "same";
}

/** Latest scan per domain, each with the scan before it (for showing a trend). */
export function latestPerDomain(list: HistoryEntry[]): Array<{ entry: HistoryEntry; previous: HistoryEntry | null }> {
  const seen = new Map<string, { entry: HistoryEntry; previous: HistoryEntry | null }>();
  for (const e of list) {
    const item = seen.get(e.domain);
    if (!item) seen.set(e.domain, { entry: e, previous: null });
    else if (!item.previous) item.previous = e;
  }
  return [...seen.values()];
}

/* ---- browser store ---- */

const listeners = new Set<() => void>();
let cache: { raw: string | null; value: HistoryEntry[] } = { raw: null, value: EMPTY };

function readRaw(): string | null {
  try {
    return window.localStorage.getItem(HISTORY_KEY);
  } catch {
    return null;
  }
}

function getSnapshot(): HistoryEntry[] {
  const raw = readRaw();
  if (raw !== cache.raw) cache = { raw, value: parseHistory(raw) };
  return cache.value;
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  const onStorage = (e: StorageEvent) => {
    if (e.key === HISTORY_KEY) listener();
  };
  window.addEventListener("storage", onStorage);
  return () => {
    listeners.delete(listener);
    window.removeEventListener("storage", onStorage);
  };
}

function save(list: HistoryEntry[]) {
  try {
    window.localStorage.setItem(HISTORY_KEY, JSON.stringify(list));
  } catch {
    // Storage blocked or full: history just isn't kept.
  }
  listeners.forEach((l) => l());
}

export function recordScan(entry: HistoryEntry): HistoryEntry | null {
  const { list, previous } = withScan(getSnapshot(), entry);
  save(list);
  return previous;
}

export function clearHistory() {
  try {
    window.localStorage.removeItem(HISTORY_KEY);
  } catch {}
  listeners.forEach((l) => l());
}

export function useScanHistory(): HistoryEntry[] {
  return useSyncExternalStore(subscribe, getSnapshot, () => EMPTY);
}
