// TTL cache with in-flight dedup.
//
// A process-wide singleton on purpose: the point is cross-panel sharing (the
// metrics panel peeks the kube panel, the incident report peeks everything),
// and passing one instance through every constructor would buy nothing but
// plumbing.

interface Entry {
  at: number;
  ttl: number;
  data?: unknown;
  err?: Error;
}

const store = new Map<string, Entry>();
const inflight = new Map<string, Promise<unknown>>();

/**
 * Returns the fresh value under key, or runs fn once — concurrent callers for
 * the same key share one upstream call. With failTtl > 0 a failure is cached
 * briefly too, so a broken upstream is not hammered on every poll.
 */
export async function cached<T>(
  key: string,
  ttl: number,
  fn: () => Promise<T>,
  failTtl = 0,
): Promise<T> {
  const hit = store.get(key);
  if (hit && Date.now() - hit.at < hit.ttl) {
    if (hit.err) throw hit.err;
    return hit.data as T;
  }

  const running = inflight.get(key);
  if (running) return running as Promise<T>;

  const promise = (async () => {
    try {
      const data = await fn();
      store.set(key, { at: Date.now(), ttl, data });
      return data;
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      if (failTtl > 0) store.set(key, { at: Date.now(), ttl: failTtl, err });
      throw err;
    } finally {
      inflight.delete(key);
    }
  })();

  inflight.set(key, promise);
  return promise;
}

/** Returns the cached value even when stale. */
export function peek<T>(key: string): T | undefined {
  const e = store.get(key);
  if (e && !e.err) return e.data as T;
  return undefined;
}

export function put(key: string, ttl: number, data: unknown): void {
  store.set(key, { at: Date.now(), ttl, data });
}

/** Drops every key with the prefix; "" clears the lot. */
export function invalidate(prefix: string): void {
  for (const k of store.keys()) {
    if (k.startsWith(prefix)) store.delete(k);
  }
}
