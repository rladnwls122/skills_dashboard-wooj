import "server-only";

// The grader's view of this environment, computed from the same logs the rest
// of the dashboard reads. The definitions are taken from the load generator
// (skills-grader) so the numbers here mean what the scorer means:
//
//   availability  = 기대 코드 && 응답 ≤ 5s        (per API)
//   performance   = availability && 응답 ≤ SLO    (user/product 0.2s, stress 1.0s)
//   image download= /images/*.png 응답 200 비율
//   exception     = 비정상 요청이 403(차단) 또는 비-API 경로 404 로 끝난 비율
//
// Two things are deliberately NOT replicated. The grader knows which request it
// meant to send, so it can compare against a per-request expected code; a log
// line only says what happened. And cost ratio is outside the tool entirely.
// Both are called out on screen rather than guessed at.

import { APP_TRAFFIC_PATHS, ENV, isAppTrafficPath, isLowPriorityPath } from "./config";
import { runInsightsQuery } from "./logsinsights";
import { PARSE_FIELDS } from "./logfields";
import type { GradingApi, GradingPanel, GradingScore, ResolvedWindow } from "@/lib/types";

export const AVAIL_DEADLINE_MS = 5_000;
export const SLO_MS: Record<GradingApi, number> = { user: 200, product: 200, stress: 1_000 };
export const GRADING_APIS: GradingApi[] = ["user", "product", "stress"];

// Observed value for one grading key. No points are assigned here: the score is
// the grader's to compute from its own run, and a number invented on this side
// would compete with it. What this panel does is line the observed traffic up
// against the same keys, so it is obvious which measurement moves which key.
function measure(label: string, okCount: number, total: number): GradingScore {
  return {
    label,
    pct: total > 0 ? Math.round((okCount / total) * 1000) / 10 : 0,
    okCount,
    total,
  };
}

// Which API a path belongs to. Anything outside the served surface is not an
// API request and never counts toward availability.
export function apiOf(path: string): GradingApi | null {
  const p = path.split("?")[0] ?? path;
  for (const api of GRADING_APIS) {
    const base = `/v1/${api}`;
    if (p === base || p.startsWith(`${base}/`)) return api;
  }
  return null;
}

export function isImagePath(path: string): boolean {
  const p = path.split("?")[0] ?? path;
  return p.startsWith("/images/");
}

// One Insights pass over the app log. Availability and both SLO tiers are
// counted in the query rather than pulled back as rows: the rows would be the
// whole traffic volume, and the counts are all the scorer needs.
export function buildGradingQuery(): string {
  return [
    PARSE_FIELDS,
    "filter ispresent(status) and ispresent(path)",
    "stats count(*) as total," +
      ` sum(status >= 200 and status < 300 and latency_ms <= ${AVAIL_DEADLINE_MS}) as availOk,` +
      ` sum(status >= 200 and status < 300 and latency_ms <= ${SLO_MS.user}) as fastOk,` +
      ` sum(status >= 200 and status < 300 and latency_ms <= ${SLO_MS.stress}) as slowOk,` +
      " sum(status = 404 or status = 403) as handledOk" +
      " by path",
    "sort total desc",
    "limit 200",
  ].join(" | ");
}

interface PathRow {
  path: string;
  total: number;
  availOk: number;
  fastOk: number;
  slowOk: number;
  handledOk: number;
}

export function toPathRow(row: Record<string, string>): PathRow {
  const num = (k: string): number => {
    const n = Number(row[k] ?? "0");
    return Number.isFinite(n) ? n : 0;
  };
  return {
    path: row["path"] ?? "",
    total: num("total"),
    availOk: num("availOk"),
    fastOk: num("fastOk"),
    slowOk: num("slowOk"),
    handledOk: num("handledOk"),
  };
}

// Builds the panel from already-fetched pieces so the scoring itself is pure.
export function buildGradingPanel(params: {
  rows: PathRow[];
  // Requests the firewall blocked outright. They never reach the app, so they
  // are not in `rows` — reported next to the exception figure rather than
  // folded into it, because the two come from different sources.
  wafBlocked: number;
  window: ResolvedWindow;
  source: string;
  scannedBytes: number;
  notes: string[];
}): GradingPanel {
  const perApi = new Map<GradingApi, { total: number; availOk: number; sloOk: number }>();
  for (const api of GRADING_APIS) perApi.set(api, { total: 0, availOk: 0, sloOk: 0 });
  let imgTotal = 0;
  let imgOk = 0;
  // Off-surface requests — the shape the grader sends as "abnormal" — and how
  // many the app ended with 404/403 as the contract requires.
  let excTotal = 0;
  let excOk = 0;

  for (const r of params.rows) {
    if (isImagePath(r.path)) {
      imgTotal += r.total;
      imgOk += r.availOk;
      continue;
    }
    const api = apiOf(r.path);
    if (!api) {
      if (!isLowPriorityPath(r.path) && !isAppTrafficPath(r.path)) {
        excTotal += r.total;
        excOk += r.handledOk;
      }
      continue;
    }
    const acc = perApi.get(api)!;
    acc.total += r.total;
    acc.availOk += r.availOk;
    // The SLO differs per API, so the right column is picked here rather than
    // baked into the query.
    acc.sloOk += SLO_MS[api] <= SLO_MS.user ? r.fastOk : r.slowOk;
  }

  // Ordered by the grader's own key order so the two read side by side.
  const lines = [
    ...GRADING_APIS.map((api) => {
      const a = perApi.get(api)!;
      return measure(`(${api}) availability`, a.availOk, a.total);
    }),
    ...GRADING_APIS.map((api) => {
      const a = perApi.get(api)!;
      return measure(`(${api}) performance`, a.sloOk, a.total);
    }),
    measure("image download", imgOk, imgTotal),
    measure("Exception Handling", excOk, excTotal),
  ];

  return {
    lines,
    window: params.window,
    source: params.source,
    scannedBytes: params.scannedBytes,
    notes: [
      ...params.notes,
      `Exception Handling 은 앱 로그에 남은 미지정 경로 요청 기준 — WAF 가 차단한 요청은 앱에 도달하지 않아 이 분모에 없다. 같은 구간 WAF 차단 ${params.wafBlocked}건은 별도 집계.`,
      `가용성은 2xx && ${AVAIL_DEADLINE_MS / 1000}s 이내, 성능은 그중 SLO(user·product ${SLO_MS.user}ms / stress ${SLO_MS.stress}ms) 이내 비율`,
      "채점기는 요청마다 기대 코드(생성 201·조회 200)를 알고 비교하지만 로그에는 그 의도가 없어 2xx 로 근사함 — 채점기 값과 다를 수 있음",
      "점수는 매기지 않는다. 이 표는 관측값을 채점기 키에 맞춰 정렬해 둔 것이고, 점수는 채점기 실행 결과(results_<비번호>.log)가 정한다.",
      `서비스 경로: ${APP_TRAFFIC_PATHS.join(", ")}`,
    ],
  };
}

// The one AWS-touching function here: run the query, hand the rows to the pure
// builder above. Cached like every other Insights read — it bills per byte.
export async function fetchGradingPanel(
  win: ResolvedWindow,
  wafBlocked: number,
): Promise<GradingPanel> {
  const res = await runInsightsQuery({
    logGroup: ENV.appLogGroup,
    query: buildGradingQuery(),
    startMs: win.startMs,
    endMs: win.endMs,
  });
  return buildGradingPanel({
    rows: res.rows.map(toPathRow),
    wafBlocked,
    window: win,
    source: `앱 로그 Logs Insights(${ENV.appLogGroup})`,
    scannedBytes: res.bytesScanned,
    notes: [],
  });
}
