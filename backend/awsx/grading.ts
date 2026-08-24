// The grader's view of this environment. The keys are the ones the 2026
// national task-3 scoring sheet (and its results_<비번호>.log) actually carry:
// "image download" and "Exception Handling" (비정상 요청 처리), and per-API
// "availability" and "performance ≤ SLO" for user · product · stress. Each key
// is measured from the source that can see it — the app log for the four served
// ratios, the WAF log for the 403 side of Exception Handling.
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
 * Image delivery: S3 objects served under /images/<object path> through the
 * same endpoint as the APIs. It is a scoring key of its own ("image download"),
 * not part of any API's availability, so it has to be split out before apiOf
 * ever sees the row.
 */
export function isImagePath(path: string): boolean {
  const p = path.split("?")[0]!;
  return p === "/images" || p.startsWith("/images/");
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

/**
 * The score bands the 2026 sheet pays on, highest first. Every percentage key
 * uses the same ladder, and each rung crossed is worth 0.5점 — so the number an
 * operator needs is not "86.2%" but "one band below the next 0.5, and 1.3%p
 * away from it". Kept as numbers rather than a formatted string so the gap can
 * be computed against them.
 */
const SCORE_BANDS_AVAILABILITY = [90, 87.5, 85, 82.5, 80, 70, 50, 30];

/**
 * 비정상 요청 처리 (image download · Exception Handling) pays on four rungs,
 * not eight. Same shape, different ladder — do not merge them.
 */
const SCORE_BANDS_ABNORMAL = [90, 85, 80, 50];

function bandOf(pct: number, bands: number[]): { tier: string | null; nextTier: string | null } {
  // bands is descending, so the first rung at or below the value is the one it
  // has already earned; the rung above it is what the next 0.5점 costs.
  let earnedIndex = -1;
  for (let i = 0; i < bands.length; i++) {
    if (pct >= bands[i]!) {
      earnedIndex = i;
      break;
    }
  }
  const tier = earnedIndex >= 0 ? `${bands[earnedIndex]!}% 구간` : null;
  const nextValue = earnedIndex === -1 ? bands[bands.length - 1]! : bands[earnedIndex - 1];
  if (nextValue === undefined) return { tier, nextTier: null };
  const gap = Math.round((nextValue - pct) * 10) / 10;
  return { tier, nextTier: `${nextValue}% 까지 ${gap}%p` };
}

/** Builds the panel from already-fetched pieces so the scoring itself is pure. */
export function buildGradingPanel(p: GradingParams): GradingPanel {
  const wafRows = p.wafRows ?? [];
  const trapLeaked = p.trapLeaked ?? 0;

  const perApi = new Map<string, { total: number; availOk: number; sloOk: number }>();
  for (const api of GRADING_APIS) perApi.set(api, { total: 0, availOk: 0, sloOk: 0 });

  // Image delivery is its own scoring key (1-1 ~ 1-4) and its own surface: S3
  // objects served under /images/ through the same endpoint. Its SLO is the
  // availability deadline itself — 5s for both — so there is no second tier.
  let imageTotal = 0;
  let imageOk = 0;

  // Requests to paths the task does not serve. The contract is 404 there, and
  // "Exception Handling" is what the grader calls the ratio that ends correctly.
  let undefTotal = 0;
  let undefOk = 0;

  for (const r of p.rows) {
    if (isImagePath(r.path)) {
      imageTotal += r.total;
      imageOk += r.availOk;
      continue;
    }
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

  // WAF side. A block on the served surface is an abnormal request answered
  // 403 — which is what the task asks for. A block on an undefined path is a
  // 404 that became a 403, which is the violation, so it only ever enlarges
  // the denominator.
  let wafServedBlocked = 0;
  let wafUndefBlocked = 0;
  for (const w of wafRows) {
    if (w.action !== "BLOCK") continue;
    if (isImagePath(w.uri)) continue;
    if (apiOf(w.uri) !== "") {
      wafServedBlocked += w.count;
      continue;
    }
    if (!isLowPriorityPath(w.uri)) wafUndefBlocked += w.count;
  }

  const appSrc = "앱 로그";
  const wafSrc = p.wafAvailable ? "WAF 로그" : "WAF 로그 없음";
  const lines: GradingScore[] = [];

  const push = (
    label: string,
    okCount: number,
    total: number,
    source: string,
    bands: number[],
    approximate: boolean,
  ): void => {
    const line = measure(label, okCount, total, source, approximate);
    const { tier, nextTier } = bandOf(line.pct, bands);
    lines.push({ ...line, tier: total > 0 ? tier : null, nextTier: total > 0 ? nextTier : null });
  };

  // Ordered exactly as the sheet lists them, so the two read side by side.
  push("image download", imageOk, imageTotal, appSrc, SCORE_BANDS_ABNORMAL, false);
  // Numerator = abnormal requests the WAF turned into 403 + undefined-path
  // requests the app ended as 404. Denominator adds what leaked to the app and
  // what the WAF wrongly blocked on an undefined path.
  push(
    "Exception Handling",
    wafServedBlocked + undefOk,
    wafServedBlocked + undefOk + trapLeaked + (undefTotal - undefOk) + wafUndefBlocked,
    `${wafSrc} + ${appSrc}`,
    SCORE_BANDS_ABNORMAL,
    true,
  );
  for (const api of GRADING_APIS) {
    const acc = perApi.get(api)!;
    push(`(${api}) availability`, acc.availOk, acc.total, appSrc, SCORE_BANDS_AVAILABILITY, false);
  }
  for (const api of GRADING_APIS) {
    const acc = perApi.get(api)!;
    push(
      `(${api}) performance ≤ ${(SLO_MS[api]! / 1000).toFixed(1)}s`,
      acc.sloOk,
      acc.total,
      appSrc,
      SCORE_BANDS_AVAILABILITY,
      false,
    );
  }

  const notes = [
    ...(p.notes ?? []),
    `채점기 로그(results_<비번호>.log)의 키 이름을 그대로 썼다 — image download · Exception Handling · (api) availability · (api) performance. cost ratio 는 이 화면이 아니라 아래 노드 대수 패널이 다룬다.`,
    `availability = 2xx && ${AVAIL_DEADLINE_MS / 1000}s 이내. performance = 그중 SLO(user·product ${SLO_MS.user}ms / stress ${SLO_MS.stress}ms) 이내. image download 는 둘 다 ${AVAIL_DEADLINE_MS / 1000}s 라 한 줄뿐이다.`,
    "채점기의 응답시간은 **클라이언트 도착 기준**이고 이 표는 앱이 기록한 처리 시간이다 — 네트워크·ALB·CloudFront 구간이 빠져 있어 항상 낙관적으로 보인다. 실제 점수는 이 값보다 낮게 나온다고 보는 편이 안전하다.",
    "분모는 앱 로그의 [GIN] 액세스 라인 전체라 앱이 스스로 내는 403(username 중복)·400·500 도 들어간다. 채점기는 자신이 보낸 요청만 세므로 값이 다를 수 있다.",
    `Exception Handling: 분자 = WAF BLOCK(서비스 경로) + 앱이 404 로 끝낸 미지정 경로. 분모에 앱까지 새어 들어온 비정상 요청 ${trapLeaked}건과 WAF 가 미지정 경로를 막아 403 이 된 ${wafUndefBlocked}건을 더했다 — 후자는 그 자체로 계약 위반이다.`,
    "구간 표시는 채점표의 문턱(90 / 87.5 / 85 / 82.5 / 80 / 70 / 50 / 30%, 비정상 처리는 90 / 85 / 80 / 50%)에 맞춘 것이다. 다음 문턱까지 남은 %p 가 곧 다음 0.5점이다.",
    "점수는 매기지 않는다. 이 표는 관측값을 채점기 키에 맞춰 정렬해 둔 것이고, 점수는 채점 플랫폼이 정한다.",
    "서비스 경로: " + appTrafficPaths().join(", "),
  ];
  if (!p.wafAvailable) {
    notes.push(
      "WAF_LOG_GROUP 이 비어 있어 Exception Handling 의 403 쪽 분자가 0 이다 — 앱 로그만으로는 차단 건수를 볼 수 없다. 설정에서 WAF 로그 그룹을 지정하면 채워진다.",
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
