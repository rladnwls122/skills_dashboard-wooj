import "server-only";

// Assembles a WAFv2 RegexPatternSet rule for one purpose — suspicious paths,
// suspicious User-Agents, or SQL injection — out of what the environment is
// actually seeing. Pure and AWS-free apart from the summary it is handed, so
// the pattern rules below are unit-testable without a cloud call.
//
// Pattern conventions (they hold for every kind, and the evaluator depends on
// them):
//
//   - One regex per line. A RegexPatternSet treats each entry as its own
//     record; a rule matches when ANY entry matches.
//   - Patterns are written in lowercase only, because every kind applies a
//     LOWERCASE transform first. An uppercase A-Z in the pattern could never
//     match the transformed input.
//   - Literals are escaped: . ( ) [ ] ? + * and friends are matched as text.
//   - RE2 syntax only — \s+ rather than the POSIX [[:space:]], which the WAF
//     regex engine rejects.
//   - Decoding transforms (URL_DECODE, HTML_ENTITY_DECODE, NORMALIZE_PATH,
//     COMPRESS_WHITE_SPACE) run before the match so %20, &#x2f; and /./ style
//     evasion is normalised away rather than pattern-matched.

import { ENV, WAF_REGION, isAppTrafficPath, isLowPriorityPath, normalizePath } from "./config";
import { classifyUa, spoofedUaPatterns } from "./threatsig";
import type { AssembledRule, AssembleKind, HttpSummary } from "@/lib/types";

// Fixed AWS WAF quotas (not adjustable). Exceeding either means the pattern set
// is rejected at creation time, so the assembler enforces them here rather than
// handing over JSON that only fails once it reaches AWS.
// https://docs.aws.amazon.com/waf/latest/developerguide/limits.html
export const MAX_PATTERNS_PER_SET = 10;
export const MAX_PATTERN_CHARS = 200;

// Escapes every regex metacharacter so a literal is matched as text.
export function escapeLiteral(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&");
}

// A path pattern anchored at the start and ending at a segment boundary, so
// "/admin" matches /admin and /admin/x but never /administration.
export function pathPattern(path: string): string {
  // NORMALIZE_PATH runs before the match, so the pattern has to describe the
  // resolved path — "/v1/image/../../etc/passwd" is matched as "/etc/passwd".
  const clean = normalizePath(path).toLowerCase();
  const trimmed = clean.endsWith("/") && clean.length > 1 ? clean.slice(0, -1) : clean;
  return `^${escapeLiteral(trimmed)}(/|$)`;
}

// A UA pattern matched anywhere in the header, with tool names held to a
// word-ish boundary so "nmap" does not fire inside "nmapper-client".
export function uaPattern(needle: string): string {
  return `(^|[^a-z0-9])${escapeLiteral(needle.toLowerCase())}([^a-z0-9]|$)`;
}

// The fixed SQL-injection signature set. These are the shapes that are never
// legitimate query text, written against a URL_DECODE + HTML_ENTITY_DECODE +
// COMPRESS_WHITE_SPACE + LOWERCASE pipeline: whitespace has already been
// collapsed to single spaces, so \s+ is enough and no case folding is needed.
// Grouped by attack shape rather than one signature per line: a pattern set
// holds at most MAX_PATTERNS_PER_SET records, so related signatures share a
// record through alternation instead of spending one each.
export const SQLI_PATTERNS = [
  "union\\s+(all\\s+)?select|select\\s+.+\\s+from\\s+",
  "insert\\s+into\\s+|drop\\s+table\\s+|;\\s*(select|insert|update|delete|drop)\\b",
  "\\bor\\s+1\\s*=\\s*1\\b|\\bor\\s+'[^']*'\\s*=\\s*'|(^|[^a-z])(and|or)\\s+\\d+\\s*=\\s*\\d+",
  "sleep\\s*\\(\\s*\\d+\\s*\\)|benchmark\\s*\\(|waitfor\\s+delay\\s+",
  "load_file\\s*\\(|into\\s+outfile\\s+",
  "information_schema",
  "--\\s*$|/\\*.*\\*/",
] as const;

interface KindSpec {
  name: string;
  setName: string;
  // Every field the same pattern set is applied to. More than one produces an
  // OrStatement — a query-string injection and a request-body injection are the
  // same attack and deserve the same rule.
  fields: Record<string, unknown>[];
  // Applied in Priority order before the match.
  transforms: string[];
  notes: string[];
}

const SPEC: Record<AssembleKind, KindSpec> = {
  path: {
    name: "dash-regex-path",
    setName: "dash-suspicious-paths",
    fields: [{ UriPath: {} }],
    // NORMALIZE_PATH collapses /./ and /../ before the anchor is applied, so a
    // request for /x/./admin cannot slip past a ^/admin pattern.
    transforms: ["URL_DECODE", "NORMALIZE_PATH", "LOWERCASE"],
    notes: [
      "관측된 경로 중 서비스 경로(APP_TRAFFIC_PATHS)와 헬스체크를 뺀 것만 패턴화 — 정상 트래픽은 매칭되지 않음",
      "URL_DECODE + NORMALIZE_PATH 를 먼저 적용해 %2f·/./ 인코딩 우회를 정규화한 뒤 매칭",
      "^/경로(/|$) 형태라 하위 경로는 잡고 접두어가 같은 다른 경로(/admin 대 /administration)는 잡지 않음",
    ],
  },
  ua: {
    name: "dash-regex-ua",
    setName: "dash-threat-uas",
    fields: [{ SingleHeader: { Name: "user-agent" } }],
    transforms: ["URL_DECODE", "COMPRESS_WHITE_SPACE", "LOWERCASE"],
    notes: [
      "공격 도구·위조 시그니처로 분류된 User-Agent만 패턴화 — Go 클라이언트와 일반 브라우저는 제외",
      "COMPRESS_WHITE_SPACE 로 공백을 정규화한 뒤 소문자 매칭",
      "단어 경계를 둬서 도구 이름이 다른 토큰 안에 포함된 경우는 매칭하지 않음",
    ],
  },
  sqli: {
    name: "dash-regex-sqli",
    setName: "dash-sqli-signatures",
    // QueryString alone would miss a POST body payload, which is where an
    // injection usually lives once a form is involved.
    fields: [{ QueryString: {} }, { Body: {} }],
    transforms: ["URL_DECODE", "HTML_ENTITY_DECODE", "COMPRESS_WHITE_SPACE", "LOWERCASE"],
    notes: [
      "관측과 무관한 고정 시그니처 세트 — 트래픽이 조용해도 항상 같은 패턴을 냄",
      "쿼리 문자열과 요청 본문을 모두 검사 (OrStatement) — POST 본문에 실린 주입도 잡음",
      "URL_DECODE + HTML_ENTITY_DECODE 로 %20·&#x2f; 인코딩 우회를 먼저 풀고, COMPRESS_WHITE_SPACE 로 공백 삽입 우회를 정규화",
      "본문은 WAF 검사 상한까지만 읽힘 — CloudFront 기본 16KB(최대 64KB로 상향 가능), ALB 는 8KB 고정. 그 뒤에 실린 주입은 놓침",
      "AWS 관리형 SQLi 규칙 그룹과 겹칠 수 있음 — 중복 차단이 문제되면 COUNT 로 먼저 확인",
    ],
  },
};

// A regex pattern set is its own AWS resource: it is created first, gets an
// ARN, and the rule references that ARN. So the two artefacts are produced
// separately — the set contents to create, and the rule that points at them.
//
// The rule handed to the console therefore carries an ARN placeholder, not the
// set name: a name in the ARN field is rejected at creation time, and would
// have failed only after the operator pasted it. The sandbox is the one place
// that takes patterns inline, so it gets its own copy of the JSON.
function chunkSets(spec: KindSpec, patterns: string[]): { name: string; patterns: string[] }[] {
  const chunks: string[][] = [];
  for (let i = 0; i < patterns.length; i += MAX_PATTERNS_PER_SET) {
    chunks.push(patterns.slice(i, i + MAX_PATTERNS_PER_SET));
  }
  return chunks.map((pats, i) => ({
    name: chunks.length === 1 ? spec.setName : `${spec.setName}-${i + 1}`,
    patterns: pats,
  }));
}

// What stands in for a set's ARN until the operator creates it and pastes the
// real one back. Shaped like an ARN so the placeholder is obviously not a value
// to leave in place.
export function placeholder(setName: string): string {
  return `<${setName}-ARN>`;
}

// The CLI that creates one set. Printed rather than run: creating resources is
// the operator's call, and the command is reviewable before it happens.
function createSetCli(setName: string, patterns: string[]): string {
  const list = JSON.stringify(patterns.map((RegexString) => ({ RegexString })));
  return [
    "aws wafv2 create-regex-pattern-set",
    `--name ${setName}`,
    `--scope ${ENV.wafScope}`,
    `--region ${WAF_REGION}`,
    `--regular-expression-list '${list}'`,
  ].join(" ");
}

// `arnFor` decides what goes in the ARN field: a placeholder for the console
// copy, the bare set name for the sandbox (its evaluator resolves inline sets
// by name).
function buildRule(
  spec: KindSpec,
  sets: { name: string; patterns: string[] }[],
  action: "BLOCK" | "COUNT",
  arnFor: (setName: string) => string,
  inlineSets: boolean,
): string {
  const transforms = spec.transforms.map((Type, Priority) => ({ Priority, Type }));

  // Every (set × field) pair gets its own reference statement; they are OR'd
  // because a match in any set on any field is the same finding.
  const refs = sets.flatMap((set) =>
    spec.fields.map((FieldToMatch) => ({
      RegexPatternSetReferenceStatement: {
        ARN: arnFor(set.name),
        FieldToMatch,
        TextTransformations: transforms,
      },
    })),
  );

  const rule = {
    Name: spec.name,
    Priority: 100,
    Statement: refs.length === 1 ? refs[0] : { OrStatement: { Statements: refs } },
    Action: action === "BLOCK" ? { Block: {} } : { Count: {} },
    VisibilityConfig: {
      SampledRequestsEnabled: true,
      CloudWatchMetricsEnabled: true,
      MetricName: spec.name,
    },
  };

  return JSON.stringify(
    inlineSets
      ? {
          // Sandbox-only: the local evaluator reads pattern sets from the top
          // level, which is how a rule can be judged before the set exists.
          RegexPatternSets: Object.fromEntries(sets.map((s) => [s.name, s.patterns])),
          Rules: [rule],
        }
      : rule,
    null,
    2,
  );
}

// Builds the rule for one purpose. `summary` is only read for the observed
// kinds; "sqli" ignores it entirely.
export function assembleRule(kind: AssembleKind, summary: HttpSummary): AssembledRule {
  const spec = SPEC[kind];
  const patterns: string[] = [];
  const evidence: string[] = [];

  if (kind === "path") {
    // Off-surface paths only: anything the environment actually serves, or a
    // health check, would be a false positive by construction.
    const seen = new Set<string>();
    for (const p of summary.byPath) {
      if (!p.path.startsWith("/")) continue;
      if (isLowPriorityPath(p.path) || isAppTrafficPath(p.path)) continue;
      const pattern = pathPattern(p.path);
      if (seen.has(pattern)) continue;
      seen.add(pattern);
      patterns.push(pattern);
      // Show the resolved path when normalisation changed it, so the operator
      // sees why a "/v1/…" request produced an "/etc/passwd" pattern.
      const resolved = normalizePath(p.path);
      const shown = resolved === (p.path.split("?")[0] ?? p.path) ? p.path : `${p.path} → ${resolved}`;
      evidence.push(
        `${shown} — ${p.count}건${p.blocked > 0 ? ` (차단 ${p.blocked})` : ""}${p.suspicious ? " · 의심 경로" : ""}`,
      );
    }
    if (patterns.length === 0) {
      throw new Error(
        "서비스 경로 밖에서 관측된 경로가 없음 — 패턴으로 만들 대상이 없습니다. (SQLi 는 관측과 무관하게 생성됩니다)",
      );
    }
  } else if (kind === "ua") {
    const seen = new Set<string>();
    for (const ua of summary.byUa) {
      const hit = classifyUa(ua.key);
      if (!hit) continue;
      // A SCANNER/RECON label is the tool name as it appears in the UA, so it
      // works as a literal. A SPOOFED label is a category name that appears
      // nowhere in the UA — using it as a literal would build a rule that
      // matches nothing, so those come from threatsig as regexes.
      const fresh =
        hit.category === "SPOOFED" ? spoofedUaPatterns(hit.label) : [uaPattern(hit.label)];
      let added = false;
      for (const pattern of fresh) {
        if (seen.has(pattern)) continue;
        seen.add(pattern);
        patterns.push(pattern);
        added = true;
      }
      if (added) {
        evidence.push(`"${ua.key}" — ${ua.count}건 · ${hit.category} 시그니처 "${hit.label}"`);
      }
    }
    if (patterns.length === 0) {
      throw new Error(
        "공격 도구·위조로 분류된 User-Agent 가 관측되지 않음 — 패턴으로 만들 대상이 없습니다.",
      );
    }
  } else {
    patterns.push(...SQLI_PATTERNS);
    evidence.push(`고정 시그니처 ${SQLI_PATTERNS.length}건 (관측 트래픽과 무관)`);
  }

  const tooLong = patterns.filter((p) => p.length > MAX_PATTERN_CHARS);
  if (tooLong.length > 0) {
    throw new Error(
      `정규식 ${MAX_PATTERN_CHARS}자 한도를 넘는 패턴이 있음: ${tooLong.map((p) => p.slice(0, 40)).join(", ")}`,
    );
  }

  // A pattern set holds at most MAX_PATTERNS_PER_SET records, so more patterns
  // than that become more sets — nothing is dropped. Each set is referenced by
  // its own statement and the statements are OR'd together.
  const sets = chunkSets(spec, patterns);
  const setCount = sets.length;
  const capNote =
    setCount > 1
      ? [
          `패턴 ${patterns.length}개를 세트 ${setCount}개로 나눠 담음 — 세트당 정규식 ${MAX_PATTERNS_PER_SET}개가 AWS 고정 한도라, 나머지는 버리지 않고 세트를 늘려 OrStatement 로 묶었습니다. 콘솔에서는 정규식 패턴 세트를 ${setCount}개 만들고 각 ARN 을 넣으세요 (계정·리전당 패턴 세트 10개가 기본 한도, 상향 요청 가능).`,
        ]
      : [];

  // Observed-path rules stay in COUNT: the path list is a sample, and a path
  // that merely looks odd is not proof. UA and SQLi signatures are never
  // legitimate traffic, so those block outright.
  const action = kind === "path" ? "COUNT" : "BLOCK";

  return {
    kind,
    name: spec.name,
    patterns,
    sets: sets.map((set) => ({
      name: set.name,
      patterns: set.patterns,
      createCli: createSetCli(set.name, set.patterns),
      arnPlaceholder: placeholder(set.name),
    })),
    ruleJson: buildRule(spec, sets, action, placeholder, false),
    sandboxRuleJson: buildRule(spec, sets, action, (n) => n, true),
    evidence,
    notes: [
      ...spec.notes,
      ...capNote,
      action === "COUNT"
        ? "Action 은 COUNT — 매칭량을 먼저 확인하고 오탐이 없을 때 Block 으로 바꾸세요."
        : "Action 은 Block — 정상 트래픽이 매칭되지 않음을 시험 탭에서 확인한 뒤 적용하세요.",
    ],
  };
}
