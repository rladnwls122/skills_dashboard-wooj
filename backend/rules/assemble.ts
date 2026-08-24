// Assembles a WAFv2 RegexPatternSet rule for one purpose out of what the
// environment is actually seeing. The pattern conventions (one regex per line,
// lowercase only, RE2, literals escaped) are AWS's, not ours.
//
// A rule is one or more *arms*, AND'd together. An arm is a pattern set matched
// against one or more fields under its own transform pipeline. Two arms is what
// the scanner rule needs: the User-Agent set alone would block a scanner
// anywhere on the site, including paths the task never serves, where the
// contract says the answer must be 404 rather than 403. Pairing "the request is
// on a served API path" with "the client is a known scanner" keeps the block
// exactly where a 403 is the wanted answer.

import { appTrafficPaths, isBenignPath, normalizePath } from "../config/paths.ts";
import type { AssembledRule, HttpSummary, RegexSetSpec } from "../../src/lib/types.ts";
import type { AssembledRuleFull } from "../types/types.ts";
import {
  CATEGORY_SPOOFED,
  CATEGORY_UNKNOWN,
  classifyUa,
  spoofedUaPatterns,
  type ThreatCategory,
} from "./threatsig.ts";

/** Fixed AWS WAF quotas (not adjustable). */
export const MAX_PATTERNS_PER_SET = 10;
export const MAX_PATTERN_CHARS = 200;

/** Escapes every regex metacharacter so a literal is matched as text. */
export function escapeLiteral(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");
}

/**
 * Anchored at the start and ending at a segment boundary, so "/admin" matches
 * /admin and /admin/x but never /administration.
 */
export function pathPattern(path: string): string {
  // NORMALIZE_PATH runs before the match, so the pattern has to describe the
  // resolved path — "/v1/image/../../etc/passwd" is matched as "/etc/passwd".
  const clean = normalizePath(path).toLowerCase();
  const trimmed = clean.endsWith("/") && clean.length > 1 ? clean.slice(0, -1) : clean;
  return "^" + escapeLiteral(trimmed) + "(/|$)";
}

/**
 * Matches anywhere in the header, with tool names held to a word-ish boundary so
 * "nmap" does not fire inside "nmapper-client".
 */
export function uaPattern(needle: string): string {
  return "(^|[^a-z0-9])" + escapeLiteral(needle.toLowerCase()) + "([^a-z0-9]|$)";
}

/**
 * Tokens every real browser also leads with. An UNKNOWN client whose first token
 * is one of these gets matched on the whole string instead — a forged UA is a
 * fixed string anyway, and the alternative is an outage.
 */
const BROWSERISH_TOKENS = new Set([
  "mozilla", "chrome", "safari", "firefox", "opera", "edge", "edg", "msie", "webkit",
]);

/**
 * The regexes that express one UA classification. A SCANNER/RECON/AUTOMATION
 * label is the tool name as it literally appears in the header, a SPOOFED label
 * is a category name that appears nowhere in it, and an UNKNOWN label is the
 * client's own leading token.
 */
export function uaPatternsFor(
  category: ThreatCategory,
  label: string,
  rawUa: string,
): string[] {
  if (category === CATEGORY_SPOOFED) return spoofedUaPatterns(label);
  // A request that sent no User-Agent at all. WAF only evaluates this when the
  // header is present-but-empty.
  if (label === "" || label.startsWith("(")) return ["^$"];
  if (category === CATEGORY_UNKNOWN && BROWSERISH_TOKENS.has(label)) {
    return ["^" + escapeLiteral(rawUa.trim().toLowerCase()) + "$"];
  }
  return [uaPattern(label)];
}

/** How an arm's patterns are produced. */
type ArmSource = "servedPaths" | "observedPaths" | "scannerUas";

/**
 * One AND-ed condition: a pattern set matched against one or more fields, under
 * its own transform pipeline. Several fields inside one arm are OR'd — a match
 * on any of them is the same finding.
 */
interface MatchArm {
  setName: string;
  source: ArmSource;
  fields: Record<string, unknown>[];
  /** Applied in Priority order before the match. */
  transforms: string[];
}

interface KindSpec {
  name: string;
  priority: number;
  action: "COUNT" | "BLOCK";
  /** AND'd together. */
  arms: MatchArm[];
  notes: string[];
}

const ASSEMBLE_SPECS: Record<string, KindSpec> = {
  path: {
    name: "dash-regex-path",
    priority: 100,
    // The path list is a sample and a path that merely looks odd is not proof.
    action: "COUNT",
    arms: [
      {
        setName: "dash-suspicious-paths",
        source: "observedPaths",
        fields: [{ UriPath: {} }],
        transforms: ["URL_DECODE", "NORMALIZE_PATH", "LOWERCASE"],
      },
    ],
    notes: [
      "관측된 경로 중 서비스 경로(APP_TRAFFIC_PATHS)와 헬스체크를 뺀 것만 패턴화 — 정상 트래픽은 매칭되지 않음",
      "URL_DECODE + NORMALIZE_PATH 를 먼저 적용해 %2f·/./ 인코딩 우회를 정규화한 뒤 매칭",
      "^/경로(/|$) 형태라 하위 경로는 잡고 접두어가 같은 다른 경로(/admin 대 /administration)는 잡지 않음",
    ],
  },
  ua: {
    name: "scanner-ua",
    priority: 30,
    action: "BLOCK",
    arms: [
      {
        // Arm 1 — where. The served API surface, so the block cannot reach a
        // path whose contract answer is 404.
        setName: "waf-api-paths",
        source: "servedPaths",
        fields: [{ UriPath: {} }],
        transforms: ["URL_DECODE", "NORMALIZE_PATH"],
      },
      {
        // Arm 2 — who. The scanner/spoofed User-Agents actually observed.
        setName: "waf-scanner-uas",
        source: "scannerUas",
        fields: [{ SingleHeader: { Name: "user-agent" } }],
        transforms: ["COMPRESS_WHITE_SPACE", "LOWERCASE"],
      },
    ],
    notes: [
      "두 조건의 AND — ①서비스 경로(APP_TRAFFIC_PATHS)로 들어온 요청이면서 ②User-Agent 가 스캐너로 분류된 경우에만 차단합니다.",
      "경로 조건을 붙이는 이유: UA 만으로 막으면 미지정 경로에도 403 이 나갑니다. 과제 계약은 미지정 경로에 404 를 요구하므로 그 자체가 위반입니다. 403 이 정답인 곳에서만 차단합니다.",
      "알려진 정상 클라이언트(렌더링 엔진을 밝힌 실제 브라우저 · Go 부하생성기 · ELB/Route53/kube 헬스체크 · 이 대시보드의 점검 요청)를 뺀 관측 User-Agent 전부를 패턴화",
      '허용 목록 방식 — 이름 붙은 공격 도구만 막으면 UA 를 위조한 쪽은 그대로 통과한다. "Mozilla/5.0 (compatible)" 처럼 아무 엔진도 밝히지 않는 문자열이 대표적',
      "SCANNER·RECON·AUTOMATION 은 도구 이름을, SPOOFED 는 페이로드 형태를, UNKNOWN 은 UA 의 첫 토큰(버전 앞부분)을 매칭 — 버전이 올라가도 계속 걸린다",
      "product 바이너리가 스스로 500 으로 응답하는 Attacker-Bot 도 SCANNER 로 분류되어 여기 포함됩니다 — WAF 가 먼저 403 으로 끊어야 하는 요청입니다.",
      "빈 User-Agent 는 ^$ 로 잡는다. 헤더 자체가 없는 요청은 SingleHeader 문장이 평가되지 않으므로 이 규칙으로는 잡히지 않는다 — 필요하면 별도 규칙이 필요",
      "경로 세트에는 NORMALIZE_PATH 만 걸고 LOWERCASE 는 걸지 않습니다 — 서비스 경로가 전부 소문자라 불필요하고, UA 쪽 파이프라인과 섞이지 않습니다.",
      "정규식 패턴 세트를 2개 만들어야 합니다 — 경로용·UA용 각각의 ARN 을 규칙 JSON 에 넣으세요.",
      "적용 전 반드시 판정해 볼 것 — 허용 목록에 없는 정상 클라이언트가 이 환경에 있다면 함께 차단된다",
    ],
  },
};

interface PatternSet {
  name: string;
  patterns: string[];
}

/** One arm resolved against the observed traffic: its sets and its evidence. */
interface BuiltArm {
  arm: MatchArm;
  sets: PatternSet[];
}

function chunkSets(setName: string, patterns: string[]): PatternSet[] {
  const chunks: string[][] = [];
  for (let i = 0; i < patterns.length; i += MAX_PATTERNS_PER_SET) {
    chunks.push(patterns.slice(i, i + MAX_PATTERNS_PER_SET));
  }
  return chunks.map((pats, i) => ({
    name: chunks.length > 1 ? `${setName}-${i + 1}` : setName,
    patterns: pats,
  }));
}

/**
 * Stands in for a set's ARN until the operator creates it and pastes the real
 * one back.
 */
export function placeholder(setName: string): string {
  return `<${setName}-ARN>`;
}

/**
 * The two settings the generated CLI needs. Kept as plain values so this module
 * stays pure.
 */
export interface AssembleEnv {
  wafScope: string;
  wafRegion: string;
}

/**
 * Printed rather than run: creating resources is the operator's call, and the
 * command is reviewable before it happens.
 */
function createSetCli(env: AssembleEnv, setName: string, patterns: string[]): string {
  const list = patterns.map((p) => ({ RegexString: p }));
  return [
    "aws wafv2 create-regex-pattern-set",
    "--name " + setName,
    "--scope " + env.wafScope,
    "--region " + env.wafRegion,
    "--regular-expression-list '" + JSON.stringify(list) + "'",
  ].join(" ");
}

/**
 * Renders the rule JSON. arnFor decides what goes in the ARN field: a
 * placeholder for the console copy, the bare set name for the sandbox.
 */
function buildRule(
  spec: KindSpec,
  built: BuiltArm[],
  action: string,
  arnFor: (setName: string) => string,
  inlineSets: boolean,
): string {
  // Within an arm, every (set × field) pair is its own reference statement and
  // they are OR'd — a match in any set on any field is the same finding. The
  // arms themselves are AND'd: each is a separate condition on the request.
  const armStatements = built.map(({ arm, sets }) => {
    const transforms = arm.transforms.map((t, i) => ({ Priority: i, Type: t }));
    const refs: Record<string, unknown>[] = [];
    for (const set of sets) {
      for (const field of arm.fields) {
        refs.push({
          RegexPatternSetReferenceStatement: {
            ARN: arnFor(set.name),
            FieldToMatch: field,
            TextTransformations: transforms,
          },
        });
      }
    }
    return refs.length > 1 ? { OrStatement: { Statements: refs } } : refs[0]!;
  });

  const statement =
    armStatements.length > 1 ? { AndStatement: { Statements: armStatements } } : armStatements[0];

  const rule = {
    Name: spec.name,
    Priority: spec.priority,
    Action: action === "BLOCK" ? { Block: {} } : { Count: {} },
    Statement: statement,
    VisibilityConfig: {
      SampledRequestsEnabled: true,
      CloudWatchMetricsEnabled: true,
      MetricName: spec.name,
    },
  };

  let doc: unknown = rule;
  if (inlineSets) {
    // Sandbox-only: the local evaluator reads pattern sets from the top level,
    // which is how a rule can be judged before the set exists.
    const setMap: Record<string, string[]> = {};
    for (const { sets } of built) for (const s of sets) setMap[s.name] = s.patterns;
    doc = { RegexPatternSets: setMap, Rules: [rule] };
  }
  return JSON.stringify(doc, null, 2);
}

/** The served API surface, as patterns. Independent of observed traffic. */
function servedPathPatterns(evidence: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const p of appTrafficPaths()) {
    const pattern = pathPattern(p);
    if (seen.has(pattern)) continue;
    seen.add(pattern);
    out.push(pattern);
    evidence.push(`${p} — 서비스 경로 (APP_TRAFFIC_PATHS)`);
  }
  if (out.length === 0) {
    throw new Error(
      "서비스 경로가 비어 있습니다 — APP_TRAFFIC_PATHS 를 설정해야 경로 조건을 만들 수 있습니다.",
    );
  }
  return out;
}

/** The observed User-Agents that are not clients this environment expects. */
function scannerUaPatterns(summary: HttpSummary, evidence: string[]): string[] {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const ua of summary.byUa) {
    const hit = classifyUa(ua.key);
    if (!hit) continue;
    const fresh = uaPatternsFor(hit.category, hit.label, ua.key);
    if (fresh.length === 0) continue;
    let added = false;
    for (const pattern of fresh) {
      if (seen.has(pattern)) continue;
      seen.add(pattern);
      out.push(pattern);
      added = true;
    }
    if (added) {
      const detail =
        hit.category === CATEGORY_UNKNOWN
          ? " UNKNOWN (알려진 정상 클라이언트가 아님)"
          : ` ${hit.category} 시그니처 "${hit.label}"`;
      evidence.push(`"${ua.key}" — ${ua.count}건 ·${detail}`);
    }
  }
  if (out.length === 0) {
    // "Nothing suspicious was seen" and "nothing was seen" need different
    // answers from the operator.
    if (summary.byUa.length === 0) {
      throw new Error(
        "User-Agent 통계가 비어 있습니다 — 관측된 UA 가 하나도 없어 규칙을 만들 수 없습니다. WAF GetSampledRequests 는 규칙에 매칭된 요청만 표본으로 남기므로, 아무것도 매칭하지 않는 WebACL 에서는 항상 0건입니다. WAF 로깅을 켜고 WAF_LOG_GROUP 을 지정하거나, 광범위한 COUNT 규칙을 하나 추가해 표본을 만드세요. (바이너리의 [GIN] 액세스 라인에는 User-Agent 가 없어 앱 로그로 대체할 수 없습니다.)",
      );
    }
    throw new Error(
      "관측된 User-Agent 가 전부 알려진 정상 클라이언트(렌더링 엔진을 밝힌 브라우저 · Go 부하생성기 · AWS 헬스체크)입니다 — 패턴으로 만들 대상이 없습니다.",
    );
  }
  return out;
}

/** Builds the rule for one purpose out of what the environment is seeing. */
export function assembleRule(
  kind: string,
  summary: HttpSummary,
  env: AssembleEnv,
): AssembledRuleFull {
  const spec = ASSEMBLE_SPECS[kind];
  if (!spec) throw new Error(`알 수 없는 규칙 종류: ${kind}`);

  const patterns: string[] = [];
  const evidence: string[] = [];
  const built: BuiltArm[] = [];

  for (const arm of spec.arms) {
    let armPatterns: string[];
    if (arm.source === "servedPaths") {
      armPatterns = servedPathPatterns(evidence);
    } else if (arm.source === "scannerUas") {
      armPatterns = scannerUaPatterns(summary, evidence);
    } else {
      armPatterns = observedPathPatterns(summary, evidence);
    }

    const tooLong = armPatterns
      .filter((p) => p.length > MAX_PATTERN_CHARS)
      .map((p) => p.slice(0, 40));
    if (tooLong.length > 0) {
      throw new Error(`정규식 ${MAX_PATTERN_CHARS}자 한도를 넘는 패턴이 있음: ${tooLong.join(", ")}`);
    }

    patterns.push(...armPatterns);
    // More patterns than the per-set cap become more sets — nothing is dropped.
    built.push({ arm, sets: chunkSets(arm.setName, armPatterns) });
  }

  const notes = [...spec.notes];
  for (const { arm, sets } of built) {
    if (sets.length > 1) {
      notes.push(
        `"${arm.setName}" 패턴을 세트 ${sets.length}개로 나눠 담음 — 세트당 정규식 ${MAX_PATTERNS_PER_SET}개가 AWS 고정 한도라, 나머지는 버리지 않고 세트를 늘려 OrStatement 로 묶었습니다. 콘솔에서 세트를 ${sets.length}개 만들고 각 ARN 을 넣으세요 (계정·리전당 패턴 세트 10개가 기본 한도, 상향 요청 가능).`,
      );
    }
  }
  notes.push(
    spec.action === "COUNT"
      ? "Action 은 COUNT — 매칭량을 먼저 확인하고 오탐이 없을 때 Block 으로 바꾸세요."
      : "Action 은 Block — 정상 트래픽이 매칭되지 않음을 확인한 뒤 적용하세요.",
  );

  const specs: RegexSetSpec[] = built.flatMap(({ sets }) =>
    sets.map((set) => ({
      name: set.name,
      patterns: set.patterns,
      createCli: createSetCli(env, set.name, set.patterns),
      arnPlaceholder: placeholder(set.name),
    })),
  );

  return {
    kind: kind as AssembledRule["kind"],
    name: spec.name,
    patterns,
    sets: specs,
    ruleJson: buildRule(spec, built, spec.action, placeholder, false),
    sandboxRuleJson: buildRule(spec, built, spec.action, (n) => n, true),
    evidence,
    notes,
  };
}

/** The observed off-surface paths, as patterns. */
function observedPathPatterns(summary: HttpSummary, evidence: string[]): string[] {
  // Off-surface paths only: anything the environment actually serves, a health
  // check, or image delivery would be a false positive by construction.
  const seen = new Set<string>();
  const out: string[] = [];
  for (const p of summary.byPath) {
    if (!p.path.startsWith("/")) continue;
    if (isBenignPath(p.path)) continue;
    const pattern = pathPattern(p.path);
    if (seen.has(pattern)) continue;
    seen.add(pattern);
    out.push(pattern);

    // Show the resolved path when normalisation changed it.
    const resolved = normalizePath(p.path);
    const base = p.path.split("?")[0]!;
    const shown = resolved !== base ? `${p.path} → ${resolved}` : p.path;
    let line = `${shown} — ${p.count}건`;
    if (p.blocked > 0) line += ` (차단 ${p.blocked})`;
    if (p.suspicious) line += " · 의심 경로";
    evidence.push(line);
  }
  if (out.length === 0) {
    throw new Error("서비스 경로 밖에서 관측된 경로가 없음 — 패턴으로 만들 대상이 없습니다.");
  }
  return out;
}
