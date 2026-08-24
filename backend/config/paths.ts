// Path policy and suspicion thresholds.
//
// One definition so the assembler, the anomaly detector and the WAF summary
// cannot disagree about what counts as normal traffic.

/** Paths excluded (or down-weighted) from anomaly scoring. */
export const LOW_PRIORITY_PATHS = [
  "/health",
  "/healthz",
  "/ready",
  "/readyz",
  "/liveness",
  "/healthcheck",
];

/**
 * WAF's NORMALIZE_PATH transform, and the only implementation of it in this
 * codebase: resolves "." and ".." segments and collapses repeated slashes.
 * Without this a traversal attempt reads as the served path it is prefixed
 * with.
 *
 * The trailing slash is kept, because that is what NORMALIZE_PATH does —
 * "/admin/" normalises to "/admin/", not "/admin". This used to be the one
 * point where this file and the rule sandbox's copy in rules/transform.ts
 * disagreed, which meant the assembler could describe a path the simulator then
 * evaluated as a different string. rules/transform.ts imports this function so
 * that cannot happen again; every comparison below is written to be
 * slash-tolerant instead.
 */
export function normalizePathSegments(value: string): string {
  const out: string[] = [];
  for (const seg of value.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") {
      out.pop();
      continue;
    }
    out.push(seg);
  }
  // segs.length === 0 would otherwise turn "/" into "//".
  const trailing = value.length > 1 && value.endsWith("/") && out.length > 0 ? "/" : "";
  return "/" + out.join("/") + trailing;
}

/**
 * The same normalisation, applied to a URI as the logs record it — query string
 * and all.
 *
 * Stripping the query is this layer's policy, not part of the transform: WAF's
 * UriPath field never carries one, but the access logs and the sampled-request
 * rows this file's callers work from do, and "/v1/user?requestid=3" is the same
 * endpoint as "/v1/user". Kept out of normalizePathSegments so a pasted rule
 * that runs NORMALIZE_PATH over a field that legitimately contains a "?" is
 * simulated the way AWS would run it.
 */
export function normalizePath(path: string): string {
  const q = path.indexOf("?");
  return normalizePathSegments(q >= 0 ? path.slice(0, q) : path);
}

export function isLowPriorityPath(path: string): boolean {
  const p = normalizePath(path);
  return LOW_PRIORITY_PATHS.some((h) => p === h || p.startsWith(h + "/"));
}

/**
 * The API surface this environment actually serves — the routes the three
 * competition binaries register (GET/POST /v1/user, GET/POST /v1/product,
 * POST /v1/stress; /healthcheck is a low-priority path). The grader's load
 * generator drives heavy traffic at these paths, so volume against them is
 * never treated as an attack.
 */
export function appTrafficPaths(): string[] {
  // /images is the static surface: S3 objects served under /images/<object
  // path> through the same endpoint. It is graded on its own key, and a WAF
  // rule that reaches it costs image download points, so it belongs on the
  // served list even though no binary registers it as a route.
  const raw =
    (process.env.APP_TRAFFIC_PATHS ?? "").trim() || "/v1/user,/v1/product,/v1/stress,/images";
  return raw
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p !== "");
}

export function isAppTrafficPath(path: string): boolean {
  const p = normalizePath(path);
  return appTrafficPaths().some((a) => p === a || p.startsWith(a + "/"));
}

/**
 * Any path segment carrying "image" is delivery, and delivery is normal here.
 * Deliberately a substring test — over-matching errs toward not blocking the
 * traffic the score depends on.
 */
export function isImageAssetPath(path: string): boolean {
  return normalizePath(path).toLowerCase().includes("image");
}

/**
 * Paths no blocking rule may ever be built against, and that no detector may
 * call suspicious.
 */
export function isBenignPath(path: string): boolean {
  return isLowPriorityPath(path) || isAppTrafficPath(path) || isImageAssetPath(path);
}

/** Concentration thresholds behind every "suspicious"/"concentrated" flag. */
export const SUSPICION = {
  pathMinCount: 30,
  pathMinShare: 0.5,
  ipMinCount: 20,
  ipMinShare: 0.3,
};

export function isPathSuspicious(path: string, count: number, total: number): boolean {
  if (isBenignPath(path)) return false;
  const t = total < 1 ? 1 : total;
  return count >= SUSPICION.pathMinCount && count / t >= SUSPICION.pathMinShare;
}

export function isIpConcentrated(count: number, total: number): boolean {
  const t = total < 1 ? 1 : total;
  return count >= SUSPICION.ipMinCount && count / t >= SUSPICION.ipMinShare;
}
