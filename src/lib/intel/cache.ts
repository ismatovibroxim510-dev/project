/**
 * Small in-memory TTL cache for third-party lookups. Concurrent requests for the
 * same key share one in-flight promise. Failures are cached briefly so a
 * rate-limited source isn't hammered. Per serverless instance, like the rate limiter.
 */
const MAX_ENTRIES = 2000;
export const FAILURE_TTL_MS = 10 * 60 * 1000;

interface Entry {
  expires: number;
  value: Promise<unknown>;
}

const store = new Map<string, Entry>();

export async function cached<T>(
  key: string,
  ttlMs: number,
  load: () => Promise<T | null>,
  now = Date.now,
): Promise<T | null> {
  const hit = store.get(key);
  if (hit && hit.expires > now()) return hit.value as Promise<T | null>;

  const value = load().catch(() => null);
  store.set(key, { expires: now() + ttlMs, value });
  if (store.size > MAX_ENTRIES) {
    for (const k of store.keys()) {
      if (store.size <= MAX_ENTRIES * 0.9) break;
      store.delete(k);
    }
  }
  const result = await value;
  // Keep failures (null) only for a short time.
  if (result === null) store.set(key, { expires: now() + FAILURE_TTL_MS, value });
  return result;
}

export function clearIntelCache() {
  store.clear();
}
