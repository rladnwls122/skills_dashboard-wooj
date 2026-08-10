import "server-only";

interface CacheEntry {
  at: number;
  ttl: number;
  data: unknown;
  error?: Error;
}

const store = new Map<string, CacheEntry>();
const inflight = new Map<string, Promise<unknown>>();

// TTL cache with in-flight dedup: concurrent callers for the same key share one
// upstream request (spec §24 — no duplicate polling, no piled-up identical calls).
// With failTtlMs set, failures are cached briefly too so a broken upstream is
// not hammered on every poll tick.
export async function cached<T>(
  key: string,
  ttlMs: number,
  fn: () => Promise<T>,
  failTtlMs = 0,
): Promise<T> {
  const hit = store.get(key);
  if (hit && Date.now() - hit.at < hit.ttl) {
    if (hit.error) throw hit.error;
    return hit.data as T;
  }

  const running = inflight.get(key);
  if (running) return running as Promise<T>;

  const p = (async () => {
    try {
      const data = await fn();
      store.set(key, { at: Date.now(), ttl: ttlMs, data });
      return data;
    } catch (e) {
      if (failTtlMs > 0) {
        const error = e instanceof Error ? e : new Error(String(e));
        store.set(key, { at: Date.now(), ttl: failTtlMs, data: null, error });
      }
      throw e;
    } finally {
      inflight.delete(key);
    }
  })();
  inflight.set(key, p);
  return p;
}

export function peekCached<T>(key: string): T | null {
  const hit = store.get(key);
  return hit ? (hit.data as T) : null;
}

export function putCached(key: string, ttlMs: number, data: unknown): void {
  store.set(key, { at: Date.now(), ttl: ttlMs, data });
}

export function invalidateCached(prefix: string): void {
  for (const k of store.keys()) if (k.startsWith(prefix)) store.delete(k);
}
