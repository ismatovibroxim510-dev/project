/**
 * Sliding-window rate limiter kept in memory.
 *
 * On Vercel each serverless instance has its own memory, so this is a per-instance
 * limit: good enough to stop casual abuse, not a hard global guarantee. For a strict
 * global limit, use Vercel WAF rate limiting or a shared store (e.g. Upstash Redis).
 */
const MAX_TRACKED_IPS = 10_000;

const hits = new Map<string, number[]>();

export interface RateLimitResult {
  ok: boolean;
  remaining: number;
  retryAfterSeconds: number;
}

export function rateLimit(key: string, limit: number, windowMs: number, now = Date.now()): RateLimitResult {
  const windowStart = now - windowMs;
  const recent = (hits.get(key) ?? []).filter((t) => t > windowStart);

  if (recent.length >= limit) {
    hits.set(key, recent);
    return { ok: false, remaining: 0, retryAfterSeconds: Math.max(1, Math.ceil((recent[0] + windowMs - now) / 1000)) };
  }

  recent.push(now);
  hits.delete(key); // re-insert so Map order approximates least-recently-used
  hits.set(key, recent);

  // Bound memory: evict the least recently active keys.
  if (hits.size > MAX_TRACKED_IPS) {
    for (const k of hits.keys()) {
      if (hits.size <= MAX_TRACKED_IPS * 0.9) break;
      hits.delete(k);
    }
  }
  return { ok: true, remaining: limit - recent.length, retryAfterSeconds: 0 };
}

/**
 * Client IP for rate limiting. On Vercel, x-real-ip / x-forwarded-for are set by
 * the platform and can't be spoofed by the client. Behind other proxies, make
 * sure they overwrite these headers.
 */
export function clientIp(headers: Headers): string {
  const real = headers.get("x-real-ip")?.trim();
  if (real) return real;
  const forwarded = headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  return forwarded || "unknown";
}
