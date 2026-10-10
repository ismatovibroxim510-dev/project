/** Client-safe Wayback helpers (no network code). */

/** "20080514210148" -> Date */
export function timestampToDate(ts: string): Date {
  return new Date(
    Date.UTC(
      +ts.slice(0, 4),
      +ts.slice(4, 6) - 1,
      +ts.slice(6, 8),
      +ts.slice(8, 10),
      +ts.slice(10, 12),
      +ts.slice(12, 14),
    ),
  );
}

/** Link to a snapshot, built from validated parts only (never from URLs in the API response). */
export function snapshotUrl(timestamp: string, domain: string): string {
  return `https://web.archive.org/web/${timestamp}/http://${domain}/`;
}
