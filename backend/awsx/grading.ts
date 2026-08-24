// The grader's view of this environment. The keys follow the 2025 national
// task-3 scoring sheet (docs/binaries.md §채점 키): per-API "로드 처리"
// (availability) and "로드 처리 <= SLO" (performance) for user · product ·
// stress, "Email Request Validation" and "비정상 요청 처리율" (abnormal
// requests answered 403), plus the task's own "undefined path → 404" contract.
//
// The scoring itself is pure; the AWS-touching function runs the Insights
// queries and hands rows to the builder. No points are assigned anywhere here —
// the score is the grader's to compute from its own run.

import {
  ACCESS_LOG_FILTER,
  cleanPath,
  MALICIOUS_TRAP_LINE,
  PARSE_FIELDS,
} from "../analysis/logfields.ts";
import { appTrafficPaths, isLowPriorityPath, normalizePath } from "../config/paths.ts";
import type { GradingPanel, GradingScore, ResolvedWindow } from "../../src/lib/types.ts";
import { errMsg, type AWS } from "./clients.ts";
import { runInsightsQuery, type InsightsRow } from "./insights.ts";

/**
 * The task sheet: every API must answer within 5 s to count as served at all;
 * user and product aim at 0.2 s, stress at 1 s.
 */
export const AVAIL_DEADLINE_MS = 5_000;

export const SLO_MS: Record<string, number> = { user: 200, product: 200, stress: 1_000 };

export const GRADING_APIS = ["user", "product", "stress"];

/** Observed value for one grading key. */
function measure(
  label: string,
  okCount: number,
  total: number,
  source: string,
  approximate: boolean,
): GradingScore {
  const pct = total > 0 ? Math.round((okCount / total) * 1000) / 10 : 0;
  return { label, pct, okCount, total, source, approximate };
}

/** "/v1/user/" and "/v1/user" are one route; only the comparison needs to say so. */
function trimTrailingSlash(path: string): string {
  return path.length > 1 && path.endsWith("/") ? path.slice(0, -1) : path;
}

/**
 * Which API a path belongs to; "" when the path is off the served surface and
 * never counts toward availability.
 */
export function apiOf(path: string): string {
  const p = path.split("?")[0]!;
  for (const api of GRADING_APIS) {
    const base = "/v1/" + api;
    if (p === base || p.startsWith(base + "/")) return api;
  }
  return "";
}

/**
 * Counts availability, both SLO tiers and the contract codes in the query
 * rather than pulling rows back — the rows would be the whole traffic volume.
 * Grouped by route (no query string), or every GET is its own row because the
 * grader's requestid rides in the query.
 */
export function buildGradingQuery(): string {
  return [
    PARSE_FIELDS,
    ACCESS_LOG_FILTER,
    "stats count(*) as total," +
      ` sum(status >= 200 and status < 300 and latency_ms <= ${AVAIL_DEADLINE_MS}) as availOk,` +
      ` sum(status >= 200 and status < 300 and latency_ms <= ${SLO_MS.user}) as fastOk,` +
      ` sum(status >= 200 and status < 300 and latency_ms <= ${SLO_MS.stress}) as slowOk,` +
      " sum(status = 404) as notFound," +
      " sum(status = 403) as forbidden," +
      " sum(status >= 500) as serverErr" +
      " by path",
    "sort total desc",
    "limit 200",
  ].join(" | ");
}

/**
 * Counts the product binary's trap line — one per Attacker-Bot request that
 * reached the app instead of being blocked.
 */
export function buildTrapQuery(): string {
  return `filter @message like "${MALICIOUS_TRAP_LINE}" | stats count(*) as leaked`;
}

/**
 * Folds the WAF log by uri × method × action. uri in the WAF log is the path
 * without its query string, so it groups like `path` does on the app side.
 */
export function buildWafGradingQuery(): string {
  return "stats count(*) as cnt by httpRequest.uri as uri, httpRequest.httpMethod as method, action | sort cnt desc | limit 500";
}

export interface PathRow {
  path: string;
  total: number;
  availOk: number;
  fastOk: number;
  slowOk: number;
  notFound: number;
  forbidden: number;
  serverErr: number;
}

function rowInt(row: InsightsRow, k: string): number {
  const n = Number.parseFloat(row[k] ?? "");
  return Number.isFinite(n) ? Math.trunc(n) : 0;
}

export function toPathRow(row: InsightsRow): PathRow {
  return {
    path: cleanPath(row.path ?? ""),
    total: rowInt(row, "total"),
    availOk: rowInt(row, "availOk"),
    fastOk: rowInt(row, "fastOk"),
    slowOk: rowInt(row, "slowOk"),
    notFound: rowInt(row, "notFound"),
    forbidden: rowInt(row, "forbidden"),
    serverErr: rowInt(row, "serverErr"),
  };
}

/** One uri × method × action cell of the WAF log. */
export interface WafRow {
  uri: string;
  method: string;
  action: string;
  count: number;
}

export function toWafRow(row: InsightsRow): WafRow {
  return {
    uri: row.uri ?? "",
    method: (row.method ?? "").toUpperCase(),
    action: (row.action ?? "").toUpperCase(),
    count: rowInt(row, "cnt"),
  };
}

export interface GradingParams {
  rows: PathRow[];
  /**
   * The WAF log fold; empty when no WAF log group is configured (wafAvailable
   * false). Requests the firewall blocked never reach the app, so they are not
   * in rows — they are what the 403 keys are made of.
   */
  wafRows?: WafRow[];
  wafAvailable?: boolean;
  /**
   * Attacker-Bot requests the app served (and answered 500) — abnormal requests
   * that leaked past the WAF.
   */
  trapLeaked?: number;
  window: ResolvedWindow;
  source?: string;
  scannedBytes?: number;
  notes?: string[];
}

/** Builds the panel from already-fetched pieces so the scoring itself is pure. */
export function buildGradingPanel(p: GradingParams): GradingPanel {
  const wafRows = p.wafRows ?? [];
  const trapLeaked = p.trapLeaked ?? 0;

  const perApi = new Map<string, { total: number; availOk: number; sloOk: number }>();
  for (const api of GRADING_APIS) perApi.set(api, { total: 0, availOk: 0, sloOk: 0 });

  // Requests to paths the binaries do not serve, and how many the app ended
  // with the 404 the task requires.
  let undefTotal = 0;
  let undefOk = 0;

  for (const r of p.rows) {
    const api = apiOf(r.path);
    if (api === "") {
      if (!isLowPriorityPath(r.path)) {
        undefTotal += r.total;
        undefOk += r.notFound;
      }
      continue;
    }
    const acc = perApi.get(api)!;
    acc.total += r.total;
    acc.availOk += r.availOk;
    // The SLO differs per API, so the right column is picked here rather than
    // baked into the query.
    if (SLO_MS[api]! <= SLO_MS.user!) acc.sloOk += r.fastOk;
    else acc.sloOk += r.slowOk;
  }

  // WAF side: blocks on the served surface are the 403s the abnormal-request
  // keys count; blocks on undefined paths are 404s that became 403s.
  let wafServedBlocked = 0;
  let wafEmailBlocked = 0;
  let wafUndefBlocked = 0;
  for (const w of wafRows) {
    if (w.action !== "BLOCK") continue;
    if (apiOf(w.uri) !== "") {
      wafServedBlocked += w.count;
      // normalizePath keeps a trailing slash because NORMALIZE_PATH does, so the
      // endpoint comparison has to trim one — "/v1/user/" is the same route the
      // grader posts to, and counting it as a different one would understate the
      // email-validation key.
      if (w.method === "POST" && trimTrailingSlash(normalizePath(w.uri)) === "/v1/user") {
        wafEmailBlocked += w.count;
      }
      continue;
    }
    if (!isLowPriorityPath(w.uri)) wafUndefBlocked += w.count;
  }

  const appSrc = "앱 로그";
  const lines: GradingScore[] = [];
  for (const api of GRADING_APIS) {
    const acc = perApi.get(api)!;
    lines.push(measure(`${api} API 로드 처리`, acc.availOk, acc.total, appSrc, false));
  }
  for (const api of GRADING_APIS) {
    const acc = perApi.get(api)!;
    lines.push(
      measure(
        `${api} API 로드 처리 ≤ ${(SLO_MS[api]! / 1000).toFixed(1)}s`,
        acc.sloOk,
        acc.total,
        appSrc,
        false,
      ),
    );
  }

  const wafSrc = p.wafAvailable ? "WAF 로그" : "WAF 로그 없음";
  // Denominator = what we saw end as 403 + what we saw get through. The
  // grader's own count of what it injected is not observable anywhere.
  lines.push(
    measure(
      "Email Request Validation (403)",
      wafEmailBlocked,
      wafEmailBlocked,
      wafSrc + " · POST /v1/user 차단 건수, 분모 없음",
      true,
    ),
  );
  lines.push(
    measure(
      "비정상 요청 처리율 (403)",
      wafServedBlocked,
      wafServedBlocked + trapLeaked,
      wafSrc + " + 앱 로그 trap 라인",
      true,
    ),
  );
  lines.push(
    measure("미지정 경로 404", undefOk, undefTotal + wafUndefBlocked, appSrc + " + WAF 차단", false),
  );

  const notes = [
    ...(p.notes ?? []),
    `로드 처리 = 2xx && ${AVAIL_DEADLINE_MS / 1000}s 이내 / 해당 API 로 들어온 요청 전체. 성능 키는 그중 SLO(user·product ${SLO_MS.user}ms / stress ${SLO_MS.stress}ms) 이내.`,
    "분모는 앱 로그의 [GIN] 액세스 라인 전체라 앱이 스스로 내는 403(username 중복 → 'It already exists in a database.')·400·500 도 들어간다. 채점기는 자신이 보낸 요청만 세므로 값이 다를 수 있다.",
    `비정상 요청 처리율: 분자 = WAF BLOCK(서비스 경로), 분모 = 분자 + 앱까지 새어 들어온 Attacker-Bot 요청 ${trapLeaked}건 (product 가 'Consumed resources by malicious attacks.' 를 찍고 500 으로 응답). 채점기가 보낸 비정상 요청 전체 수는 관측 불가 — 새는 건수가 0 인지를 본다.`,
    "Email Request Validation: WAF 가 POST /v1/user 를 차단한 건수만 보인다 — 잘못된 이메일이 몇 건 주입됐는지는 어디에도 기록되지 않는다(앱은 이메일을 검사하지 않는다). 0건이면 규칙이 없거나 COUNT 상태다.",
    "미지정 경로 404: 앱 로그의 비서비스 경로 요청 중 404 로 끝난 비율. WAF 가 미지정 경로를 BLOCK 하면 403 이 나가 위반 — 그 건수는 분모에만 더했다.",
    "점수는 매기지 않는다. 이 표는 관측값을 채점기 키에 맞춰 정렬해 둔 것이고, 점수는 채점 플랫폼이 정한다.",
    "서비스 경로: " + appTrafficPaths().join(", "),
  ];
  if (!p.wafAvailable) {
    notes.push(
      "WAF_LOG_GROUP 이 비어 있어 403 키는 앱 로그만으로 채웠다 — 차단 건수는 0 으로 보인다. 설정에서 WAF 로그 그룹을 지정하면 채워진다.",
    );
  }

  return {
    lines,
    window: p.window,
    source: p.source ?? "",
    scannedBytes: p.scannedBytes ?? 0,
    notes,
  };
}

/**
 * The one AWS-touching function here: one app-log query for the per-path stats,
 * one for the trap line, and — when a WAF log group is configured — one WAF-log
 * fold.
 */
export async function fetchGradingPanel(a: AWS, win: ResolvedWindow): Promise<GradingPanel> {
  const logGroup = a.settings.appLogGroup();
  const res = await runInsightsQuery(a, {
    logGroup,
    query: buildGradingQuery(),
    startMs: win.startMs,
    endMs: win.endMs,
  });

  const params: GradingParams = {
    rows: res.rows.map(toPathRow),
    wafRows: [],
    wafAvailable: false,
    trapLeaked: 0,
    window: win,
    source: `앱 로그 Logs Insights(${logGroup})`,
    scannedBytes: res.bytesScanned,
    notes: [],
  };

  try {
    const trap = await runInsightsQuery(a, {
      logGroup,
      query: buildTrapQuery(),
      startMs: win.startMs,
      endMs: win.endMs,
    });
    params.scannedBytes = (params.scannedBytes ?? 0) + trap.bytesScanned;
    if (trap.rows.length > 0) params.trapLeaked = rowInt(trap.rows[0]!, "leaked");
  } catch (e) {
    params.notes!.push("Attacker-Bot trap 라인 집계 실패: " + errMsg(e));
  }

  const wafGroup = a.settings.wafLogGroup();
  if (wafGroup !== "") {
    try {
      const wafRes = await runInsightsQuery(a, {
        logGroup: wafGroup,
        region: a.settings.wafRegion(),
        query: buildWafGradingQuery(),
        startMs: win.startMs,
        endMs: win.endMs,
      });
      params.wafAvailable = true;
      params.scannedBytes = (params.scannedBytes ?? 0) + wafRes.bytesScanned;
      params.source += ` + WAF 로그(${wafGroup})`;
      params.wafRows = wafRes.rows.map(toWafRow);
    } catch (e) {
      params.notes!.push("WAF 로그 집계 실패 — 403 키는 앱 로그만으로 채움: " + errMsg(e));
    }
  }

  return buildGradingPanel(params);
}
