import { afterEach, describe, expect, it, vi } from "vitest";
import {
  clearHistory,
  compareScans,
  HISTORY_KEY,
  HISTORY_MAX,
  latestPerDomain,
  parseHistory,
  recordScan,
  withScan,
  type HistoryEntry,
} from "@/lib/history";

const e = (
  domain: string,
  grade: HistoryEntry["grade"],
  score: number,
  date = "2026-01-01T00:00:00Z",
): HistoryEntry => ({
  domain,
  grade,
  score,
  date,
});

describe("scan history", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("drops malformed and hostile entries", () => {
    const raw = JSON.stringify([
      e("example.com", "A", 90),
      { domain: "<img src=x onerror=alert(1)>", grade: "A", score: 90, date: "2026-01-01" },
      { domain: "x.com", grade: "Z", score: 1, date: "2026-01-01" },
      { domain: "y.com", grade: "B", score: 500, date: "2026-01-01" },
      "nope",
    ]);
    expect(parseHistory(raw)).toEqual([e("example.com", "A", 90)]);
    expect(parseHistory("{not json")).toEqual([]);
    expect(parseHistory(null)).toEqual([]);
  });

  it("adds newest first, caps the list and returns the previous scan of the domain", () => {
    const list = Array.from({ length: HISTORY_MAX }, (_, i) => e(`site${i}.com`, "B", 70));
    const { list: next, previous } = withScan([e("example.com", "C", 60), ...list], e("example.com", "A", 90));
    expect(next[0]).toEqual(e("example.com", "A", 90));
    expect(next).toHaveLength(HISTORY_MAX);
    expect(previous).toEqual(e("example.com", "C", 60));
  });

  it("compares grades, then scores", () => {
    expect(compareScans({ grade: "C", score: 60 }, { grade: "A", score: 90 })).toBe("up");
    expect(compareScans({ grade: "A", score: 90 }, { grade: "B", score: 80 })).toBe("down");
    expect(compareScans({ grade: "B", score: 72 }, { grade: "B", score: 75 })).toBe("up");
    expect(compareScans({ grade: "B", score: 72 }, { grade: "B", score: 72 })).toBe("same");
  });

  it("groups the latest scan per domain with its predecessor", () => {
    const groups = latestPerDomain([
      e("a.com", "A", 90),
      e("b.com", "B", 70),
      e("a.com", "C", 60),
      e("a.com", "F", 10),
    ]);
    expect(groups).toHaveLength(2);
    expect(groups[0].previous?.grade).toBe("C");
    expect(groups[1].previous).toBeNull();
  });

  it("persists through localStorage", () => {
    const store = new Map<string, string>();
    vi.stubGlobal("window", {
      localStorage: {
        getItem: (k: string) => store.get(k) ?? null,
        setItem: (k: string, v: string) => store.set(k, v),
        removeItem: (k: string) => store.delete(k),
      },
      addEventListener: () => {},
      removeEventListener: () => {},
    });
    expect(recordScan(e("example.com", "C", 60))).toBeNull();
    expect(recordScan(e("example.com", "A", 90))?.grade).toBe("C");
    expect(JSON.parse(store.get(HISTORY_KEY)!)).toHaveLength(2);
    clearHistory();
    expect(store.has(HISTORY_KEY)).toBe(false);
  });

  it("keeps working when storage is blocked", () => {
    const blocked = () => {
      throw new DOMException("denied", "SecurityError");
    };
    vi.stubGlobal("window", {
      localStorage: { getItem: blocked, setItem: blocked, removeItem: blocked },
      addEventListener: () => {},
      removeEventListener: () => {},
    });
    expect(() => recordScan(e("example.com", "A", 90))).not.toThrow();
    expect(() => clearHistory()).not.toThrow();
  });
});
