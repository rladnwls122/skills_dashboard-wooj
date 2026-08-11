import "server-only";
import { APP_TRAFFIC_PATHS, isAppTrafficPath } from "./config";
import type { HttpSummary } from "@/lib/types";

// The response contract this environment's gateway is built to honour. Every
// report that leaves the dashboard states it up front, because the same status
// code means opposite things depending on which side of the contract a request
// falls on: a 404 on /login is the gateway working, a 404 on /v1/user is a
// routing failure, and a 403 is a WAF block that is only correct on a served
// path.
//
//   미지정 경로 (/v1/admin, /login, /.env …)   → 404  존재하지 않는 것처럼 보여 스캐닝 차단
//   지정 경로 (APP_TRAFFIC_PATHS) + 정상 요청  → 200  백엔드로 전달
//   지정 경로 + 비정상 요청                     → 403  WAF에서 종료
//
// "비정상"은 SQLi / XSS / Body 포맷 오류 / 차단 IP / rate limit 초과를 말한다.
export const GATEWAY_CONTRACT = {
  unlistedStatus: 404,
  normalStatus: 200,
  abnormalStatus: 403,
  abnormalKinds: [
    "SQL Injection",
    "XSS",
    "Body 포맷 오류",
    "차단 IP",
    "Rate limit 초과",
  ],
} as const;

// Amazon Q's prompt input caps at 10,000 characters — anything past it is
// silently lost, which for an incident hand-off means losing whichever section
// happened to be last. Reports built for Q are packed to fit this instead.
export const MAX_Q_PROMPT_CHARS = 10_000;

// The contract, rendered for the top of a report. Kept to five lines: this is
// the interpretation key, not the finding.
export function contractLines(): string[] {
  const c = GATEWAY_CONTRACT;
  return [
    `- 지정 경로: ${APP_TRAFFIC_PATHS.join(", ")}`,
    `- 미지정 경로(예: /v1/admin, /login, /.env) → ${c.unlistedStatus} Not Found — 엔드포인트가 없는 것처럼 보이게 하여 스캐닝 차단`,
    `- 지정 경로 + 정상 요청 → ${c.normalStatus} OK (백엔드 전달)`,
    `- 지정 경로 + 비정상 요청(${c.abnormalKinds.join(" / ")}) → ${c.abnormalStatus} Forbidden`,
    `- 따라서 ${c.unlistedStatus}/${c.abnormalStatus}는 그 자체로 장애가 아니라 정책이 동작한 결과. 5XX와 "미지정 경로의 ${c.normalStatus}"만이 계약 위반.`,
  ];
}

export interface ContractCheck {
  // Observations that match the contract — stated so a reader does not read a
  // 403/404 spike as an outage.
  conforming: string[];
  // Observations the contract does not allow. These are the findings.
  deviations: string[];
}

// Scores the sampled traffic against the contract. Deliberately hedged: WAF
// logs carry the WAF's own action (ALLOW/BLOCK), not the status the client
// finally saw, so a mismatch here is "확인 필요", never a confirmed verdict.
export function evaluateContract(h: HttpSummary | null): ContractCheck {
  const conforming: string[] = [];
  const deviations: string[] = [];
  if (!h) return { conforming, deviations };

  const c = GATEWAY_CONTRACT;
  const listed = h.byPath.filter((p) => !p.lowPriority && isAppTrafficPath(p.path));
  const unlisted = h.byPath.filter((p) => !p.lowPriority && !isAppTrafficPath(p.path));

  const unlistedBlocked = unlisted.filter((p) => p.blocked > 0);
  const unlistedPassed = unlisted.filter((p) => p.count - p.blocked > 0);
  const listedBlocked = listed.filter((p) => p.blocked > 0);

  if (unlistedPassed.length > 0) {
    const passedCount = unlistedPassed.reduce((a, p) => a + (p.count - p.blocked), 0);
    deviations.push(
      `미지정 경로 ${unlistedPassed.length}개(요청 ${passedCount}건)가 WAF를 통과 — 게이트웨이가 ${c.unlistedStatus}로 응답했는지 확인 필요 (${c.normalStatus}면 라우팅 노출): ` +
        unlistedPassed
          .slice(0, 5)
          .map((p) => `${p.path} ${p.count - p.blocked}건 통과`)
          .join(", "),
    );
  }
  if (unlistedBlocked.length > 0) {
    // A WAF Block answers 403 by default. On an unlisted path that tells the
    // scanner the path is guarded — the contract wants it indistinguishable
    // from a path that does not exist.
    deviations.push(
      `미지정 경로가 WAF에서 차단됨 → 기본 응답은 ${c.abnormalStatus}이지만 계약상 ${c.unlistedStatus}여야 함. 해당 규칙에 CustomResponse ${c.unlistedStatus} 설정 검토: ` +
        unlistedBlocked
          .slice(0, 5)
          .map((p) => `${p.path} ${p.blocked}건`)
          .join(", "),
    );
  }
  if (listedBlocked.length > 0) {
    conforming.push(
      `지정 경로 차단 ${listedBlocked.reduce((a, p) => a + p.blocked, 0)}건 → 비정상 요청에 대한 ${c.abnormalStatus}로 계약과 일치 (${listedBlocked
        .slice(0, 5)
        .map((p) => `${p.path} ${p.blocked}건`)
        .join(", ")})`,
    );
  }

  const d = h.statusDist;
  if (d) {
    if (d.c5xx > 0) {
      deviations.push(
        `5XX ${d.c5xx}건/분 — 계약에 없는 응답. 백엔드 장애이며 WAF 정책으로 설명되지 않음.`,
      );
    }
    if (d.c3xx > 0) {
      deviations.push(`3XX ${d.c3xx}건/분 — 계약에 없는 응답. 리다이렉트 경로 확인 필요.`);
    }
    if (d.c4xx > 0 && unlisted.length > 0) {
      conforming.push(
        `4XX ${d.c4xx}건/분 관측 + 미지정 경로 요청 ${unlisted.reduce((a, p) => a + p.count, 0)}건 — 스캐닝에 대한 ${c.unlistedStatus} 응답으로 설명 가능. 4XX 증가만으로 장애로 판정하지 말 것.`,
      );
    }
    if (d.c5xx === 0 && d.c3xx === 0) {
      conforming.push(`5XX/3XX 없음 — 응답 코드는 계약 범위(${c.normalStatus}/${c.abnormalStatus}/${c.unlistedStatus}) 안에 있음.`);
    }
  }

  return { conforming, deviations };
}

// Which side of the contract a path sits on. A status code says nothing on its
// own — 404 on an unlisted path is the policy working, on a listed one it is a
// routing failure — so any path listed as evidence carries this label.
export function pathScopeLabel(path: string): string {
  return isAppTrafficPath(path) ? "지정" : "미지정";
}

// What response a candidate rule should return once it moves to Block, given
// the contract. A rule scoped to an unlisted path must not answer 403: that
// tells a scanner the path is worth guarding, which is exactly what the 404
// policy exists to hide.
export function responseGuidance(path: string | undefined): string {
  const c = GATEWAY_CONTRACT;
  if (path && !isAppTrafficPath(path)) {
    return `미지정 경로 대상 — Block 기본 응답 ${c.abnormalStatus} 대신 CustomResponse ${c.unlistedStatus} 설정 권장`;
  }
  if (path) {
    return `지정 경로 대상 — Block 기본 응답 ${c.abnormalStatus}가 계약과 일치`;
  }
  return `경로 무관(UA/쿼리/IP 기준) — 지정 경로에서는 ${c.abnormalStatus}, 미지정 경로에서는 ${c.unlistedStatus}가 되도록 scope-down 또는 CustomResponse 검토`;
}

// Packs prioritised sections into a hard character budget. Sections are added
// whole while they fit; the first one that does not is truncated line-by-line
// and everything after it is named but not included, so the reader always knows
// what was dropped rather than silently receiving a shorter report.
export interface QSection {
  title: string;
  lines: string[];
}

export function packToLimit(header: string[], sections: QSection[], limit: number): string {
  const out: string[] = [...header];
  let used = out.join("\n").length;
  const omitted: string[] = [];
  // Room for the trailing "생략" notice, which is only written if needed.
  const reserve = 120;

  for (const s of sections) {
    if (s.lines.length === 0) continue;
    const titleCost = s.title.length + 2;
    if (used + titleCost + reserve > limit) {
      omitted.push(s.title);
      continue;
    }
    out.push("", s.title);
    used += titleCost;
    let kept = 0;
    for (const line of s.lines) {
      if (used + line.length + 1 + reserve > limit) break;
      out.push(line);
      used += line.length + 1;
      kept += 1;
    }
    if (kept < s.lines.length) {
      const note = `- …이하 ${s.lines.length - kept}행 생략(길이 제한)`;
      out.push(note);
      used += note.length + 1;
    }
  }

  if (omitted.length > 0) {
    out.push("", `> 길이 제한(${limit}자)으로 생략된 항목: ${omitted.join(", ")}. 전체 내용은 Markdown/JSON 산출물 참조.`);
  }

  const text = out.join("\n");
  return text.length <= limit ? text : text.slice(0, limit);
}
