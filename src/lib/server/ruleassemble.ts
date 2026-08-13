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

import {
  APP_TRAFFIC_PATHS,
  ENV,
  isBenignPath,
  isImageAssetPath,
  LOW_PRIORITY_PATHS,
  normalizePath,
  wafRegion,
} from "./config";
import { looksLikeSqli, looksLikeXss } from "./ruleinjection";
import { applyTransforms } from "./ruletransform";
import { classifyUa, spoofedUaPatterns, type ThreatCategory } from "./threatsig";
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

// Tokens every real browser also leads with. An UNKNOWN client whose first
// token is one of these cannot be matched on that token: "Mozilla/5.0
// (compatible)" and Chrome both start with "mozilla", so a rule built from the
// token would block every browser on the site. Those get matched on the whole
// string instead — less resilient to a version bump, but a forged UA is a fixed
// string anyway, and the alternative is an outage.
const BROWSERISH_TOKENS = new Set([
  "mozilla", "chrome", "safari", "firefox", "opera", "edge", "edg", "msie", "webkit",
]);

// The regexes that express one UA classification.
//
// The categories need different treatments and mixing them up produces a rule
// that silently matches nothing — or, worse, one that matches everything: a
// SCANNER/RECON/AUTOMATION label is the tool name as it literally appears in
// the header, a SPOOFED label is a category name that appears nowhere in it,
// and an UNKNOWN label is the client's own leading token.
export function uaPatternsFor(category: ThreatCategory, label: string, rawUa: string): string[] {
  if (category === "SPOOFED") return spoofedUaPatterns(label);
  // A request that sent no User-Agent at all. WAF only evaluates this when the
  // header is present-but-empty; a wholly absent header does not match a
  // SingleHeader statement, which is why the spec note says so.
  if (!label || label.startsWith("(")) return ["^$"];
  if (category === "UNKNOWN" && BROWSERISH_TOKENS.has(label)) {
    return [`^${escapeLiteral(rawUa.trim().toLowerCase())}$`];
  }
  return [uaPattern(label)];
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

// --- endpoint rules (query→403 / surface→404) --------------------------------
//
// The task-sheet contract over the served API surface (APP_TRAFFIC_PATHS):
//
//   query   — an abnormal request on a served endpoint (/v1/user?id=' or 1=1)
//             → Block + 403 커스텀 응답. Built from the OBSERVED query
//             strings: presence alone is never a match (all legitimate
//             traffic carries requestid/uuid), and the served paths are the
//             rule's scope, never its suspicion.
//   surface — a path outside the served surface does not exist here
//             → Block + 404 커스텀 응답. The allow list is the task sheet;
//             observation only previews what the rule would have blocked.
//
// The custom response carries only a ResponseCode: a CustomResponseBodyKey
// must name a body predefined in the WebACL's CustomResponseBodies map and is
// rejected with WAFInvalidParameterException otherwise, and CustomResponse is
// only legal inside a Block action. A bare code cannot fail either way.

type EndpointKind = Extract<AssembleKind, "query" | "surface">;

// The endpoints as one editable alternation: every served path is /v1/<name>,
// so the group reads /v1/(user|product|stress) and an endpoint is added or
// removed by editing the word list. Lowercase only — a LOWERCASE transform
// runs before the match. A path that doesn't fit /v1/<name> falls back to a
// full-path alternation so an APP_TRAFFIC_PATHS override stays correct.
export function endpointGroup(paths: string[]): string {
  const clean = [...new Set(paths.map((p) => normalizePath(p).toLowerCase()))];
  const tails = clean.map((p) => (/^\/v1\/[^/]+$/.test(p) ? p.slice("/v1/".length) : null));
  if (tails.every((t): t is string => t !== null)) {
    return `/v1/(${tails.map(escapeLiteral).join("|")})`;
  }
  return `(${clean.map(escapeLiteral).join("|")})`;
}

const PATH_TRANSFORMS = ["URL_DECODE", "NORMALIZE_PATH", "LOWERCASE"] as const;

function pathRegexStatement(pattern: string): Record<string, unknown> {
  return {
    RegexMatchStatement: {
      RegexString: pattern,
      FieldToMatch: { UriPath: {} },
      TextTransformations: PATH_TRANSFORMS.map((Type, Priority) => ({ Priority, Type })),
    },
  };
}

const customResponseNote = (code: number): string =>
  `커스텀 응답은 ResponseCode ${code} 만 지정 — CustomResponseBodyKey 는 WebACL 의 CustomResponseBodies 에 같은 키가 미리 정의돼 있어야 하고(없으면 WAFInvalidParameterException 거부), CustomResponse 는 Block 액션 안에서만 유효`;

const sandboxCodeNote = (code: number): string =>
  `시험 탭은 매칭·차단 여부만 판정 — 응답 코드 ${code} 자체는 로컬에서 재현되지 않음`;

function visibility(name: string): Record<string, unknown> {
  return { SampledRequestsEnabled: true, CloudWatchMetricsEnabled: true, MetricName: name };
}

// 403 — abnormal requests on the served endpoints, built from what the
// traffic actually carried. Every legitimate request here has a query string
// (the task appends requestid/uuid to all traffic), so mere presence is never
// the condition. Observation picks the patterns: a fixed SQLI_PATTERNS
// signature enters only when an observed query string actually triggered it,
// and an injected-looking query that no fixed signature covers (XSS, exotic
// payloads) becomes a literal pattern of its normalised form. The served
// paths themselves are the rule's scope, never its suspicion — a pattern is
// only ever built from the query string.
function assembleQueryRule(apiPaths: string[], summary: HttpSummary): AssembledRule {
  const name = "dash-query-403";
  const endpointPattern = `^${endpointGroup(apiPaths)}(/|$)`;
  const transforms = SPEC.sqli.transforms.map((Type, Priority) => ({ Priority, Type }));
  const compiledSigs = SQLI_PATTERNS.map((s) => new RegExp(s));

  const sigs: string[] = [];
  const literals = new Set<string>();
  const evidence: string[] = [];
  for (const q of summary.queryPatterns) {
    // Judge the query the way the WAF will see it: decoded, whitespace
    // compressed, lowercased.
    const t = applyTransforms(q.key, transforms);
    const decoded = t.ok ? t.value : q.key.toLowerCase();
    const hits = SQLI_PATTERNS.filter((_, i) => compiledSigs[i]?.test(decoded) === true);
    const injected =
      hits.length > 0 || looksLikeSqli(decoded, "HIGH") || looksLikeXss(decoded, "HIGH");
    if (!injected) continue;
    for (const h of hits) if (!sigs.includes(h)) sigs.push(h);
    // Sliced before escaping: RegexMatch is a contains-match, so a truncated
    // literal still fires, and the slice keeps it under the 200-char quota.
    if (hits.length === 0) literals.add(escapeLiteral(decoded.slice(0, 80)));
    evidence.push(
      `"${q.key}" — ${q.count}건${hits.length > 0 ? "" : " · 고정 시그니처 밖 — 리터럴 패턴화"}`,
    );
  }

  const patterns = [...sigs, ...literals];
  if (patterns.length === 0) {
    // "Nothing was seen" and "nothing suspicious was seen" need different
    // answers from the operator.
    throw new Error(
      summary.queryPatterns.length === 0
        ? "쿼리스트링 통계가 비어 있습니다 — 관측된 쿼리스트링이 없어 규칙을 만들 수 없습니다. WAF 로깅(WAF_LOG_GROUP)을 확인하세요."
        : "관측된 쿼리스트링이 전부 정상 형태(requestid·uuid 등)입니다 — 403으로 만들 대상이 없습니다. 관측과 무관한 선제 차단이 필요하면 SQL 인젝션 카드를 쓰세요.",
    );
  }
  const tooLong = patterns.filter((p) => p.length > MAX_PATTERN_CHARS);
  if (tooLong.length > 0 || endpointPattern.length > MAX_PATTERN_CHARS) {
    throw new Error(
      `정규식 ${MAX_PATTERN_CHARS}자 한도를 넘는 패턴이 있음: ${(tooLong[0] ?? endpointPattern).slice(0, 40)}`,
    );
  }

  const sets = chunkSets("dash-query-sigs", patterns);
  const refs = (arnFor: (setName: string) => string): Record<string, unknown>[] =>
    sets.map((set) => ({
      RegexPatternSetReferenceStatement: {
        ARN: arnFor(set.name),
        FieldToMatch: { QueryString: {} },
        TextTransformations: transforms,
      },
    }));
  const rule = (arnFor: (setName: string) => string): Record<string, unknown> => {
    const r = refs(arnFor);
    return {
      Name: name,
      // Distinct priorities so the 403/404 pair can land in one WebACL without
      // a duplicate-priority rejection; they match disjoint requests, so order
      // between the two does not matter.
      Priority: 110,
      Statement: {
        AndStatement: {
          Statements: [
            pathRegexStatement(endpointPattern),
            ...(r.length === 1 ? r : [{ OrStatement: { Statements: r } }]),
          ],
        },
      },
      Action: { Block: { CustomResponse: { ResponseCode: 403 } } },
      VisibilityConfig: visibility(name),
    };
  };

  return {
    kind: "query",
    name,
    patterns: [endpointPattern, ...patterns],
    sets: sets.map((set) => ({
      name: set.name,
      patterns: set.patterns,
      createCli: createSetCli(set.name, set.patterns),
      arnPlaceholder: placeholder(set.name),
    })),
    ruleJson: JSON.stringify(rule(placeholder), null, 2),
    sandboxRuleJson: JSON.stringify(
      {
        RegexPatternSets: Object.fromEntries(sets.map((s) => [s.name, s.patterns])),
        Rules: [rule((n) => n)],
      },
      null,
      2,
    ),
    evidence,
    notes: [
      "관측된 쿼리스트링(QueryString 패턴 목록) 중 인젝션 형태만 패턴화 — 쿼리스트링 존재만으로는 차단하지 않음. 이 환경의 모든 정상 요청에 requestid·uuid 쿼리스트링이 붙는다",
      "고정 시그니처는 관측에 실제로 걸린 것만 담고, 시그니처 밖 페이로드는 정규화된 형태의 리터럴로 패턴화",
      `AndStatement — 과제지의 정상 경로(${endpointPattern}) 안의 요청만 평가. 경로 자체는 의심 패턴이 아니라 적용 범위이고, 경로 밖 요청은 404 규칙 담당. 엔드포인트는 괄호 안 목록만 고치면 추가/삭제 (LOWERCASE 변환이 먼저라 항상 소문자)`,
      "URL_DECODE + HTML_ENTITY_DECODE 로 인코딩 우회를 풀고 COMPRESS_WHITE_SPACE 로 공백 삽입을 정규화한 뒤 매칭",
      customResponseNote(403),
      sandboxCodeNote(403),
    ],
  };
}

// 404 — anything off the served surface. "image" and "health" are substring
// allowances on purpose (the isBenignPath philosophy): image delivery and
// health probes arrive under more than one shape (/v1/image/…, /images/…,
// /health, /healthz, /healthcheck), and a missed block is a visible log line
// while a false 404 on scored traffic is an outage.
function assembleSurfaceRule(apiPaths: string[], summary: HttpSummary): AssembledRule {
  const name = "dash-surface-404";
  const readiness = LOW_PRIORITY_PATHS.filter((p) => !p.includes("health"));
  const readinessGroup = `^/(${readiness.map((p) => escapeLiteral(p.slice(1))).join("|")})(/|$)`;
  const pattern = `^${endpointGroup(apiPaths)}(/|$)|image|health|${readinessGroup}`;
  if (pattern.length > MAX_PATTERN_CHARS) {
    throw new Error(
      `정규식 ${MAX_PATTERN_CHARS}자 한도를 넘는 패턴이 있음: ${pattern.slice(0, 40)}`,
    );
  }
  const rule = {
    Name: name,
    Priority: 120,
    Statement: { NotStatement: { Statement: pathRegexStatement(pattern) } },
    Action: { Block: { CustomResponse: { ResponseCode: 404 } } },
    VisibilityConfig: visibility(name),
  };

  // The allow list is the task sheet, not the traffic — an allow list learned
  // from traffic would learn the attack too. Observation's job here is the
  // impact preview: which observed paths this rule would have answered 404.
  const allow = new RegExp(pattern);
  const wouldBlock = summary.byPath.filter(
    (p) => p.path.startsWith("/") && !allow.test(normalizePath(p.path).toLowerCase()),
  );

  return {
    kind: "surface",
    name,
    patterns: [pattern],
    sets: [],
    ruleJson: JSON.stringify(rule, null, 2),
    sandboxRuleJson: JSON.stringify({ Rules: [rule] }, null, 2),
    evidence: [
      `허용: ${apiPaths.join(", ")} + image·health 가 들어간 모든 경로 + ${readiness.join("·")}`,
      ...(wouldBlock.length > 0
        ? wouldBlock.map((p) => `${p.path} — ${p.count}건 · 이 규칙이 404 로 차단`)
        : ["관측 창에서 404 대상 경로는 없었음 — 규칙은 관측과 무관하게 유효"]),
    ],
    notes: [
      "NotStatement — 허용 패턴에 매칭되지 않는 모든 경로를 404 로 차단. 과제지의 정상 경로는 허용 목록이라 절대 차단되지 않음",
      "허용 목록은 트래픽이 아니라 과제지 기준 — 트래픽에서 배우면 공격 경로까지 배운다. 관측은 이 규칙이 무엇을 차단했을지 근거로만 사용",
      "image·health 는 부분 문자열 허용 — 이미지 전송과 헬스체크는 여러 형태로 오므로 넓게 허용. 넓힌 방향은 의도: 놓친 차단은 로그에 남지만 오차단은 채점 트래픽 장애",
      "엔드포인트는 괄호 안 목록만 고치면 추가/삭제 — LOWERCASE 변환이 먼저라 항상 소문자",
      "URL_DECODE + NORMALIZE_PATH 로 %2f·/./ 인코딩 우회를 정규화한 뒤 매칭",
      customResponseNote(404),
      "정규식 패턴 세트 없이 RegexMatchStatement 에 인라인 — 만들 리소스도 붙여넣을 ARN 도 없음",
      sandboxCodeNote(404),
    ],
  };
}

function assembleEndpointRule(kind: EndpointKind, summary: HttpSummary): AssembledRule {
  if (APP_TRAFFIC_PATHS.length === 0) {
    throw new Error("APP_TRAFFIC_PATHS 가 비어 있음 — 서비스 경로가 없어 규칙을 만들 수 없습니다.");
  }
  // The 403 rule scopes to every served endpoint, image delivery included: an
  // injection aimed at /v1/image is still an injection, and this rule only ever
  // fires on an observed injection signature — never on the path itself — so
  // widening the scope cannot touch normal image traffic. Leaving it out would
  // put /v1/image?id=' or 1=1 past both rules, since the 404 allow list below
  // waves anything carrying "image" through.
  if (kind === "query") return assembleQueryRule(APP_TRAFFIC_PATHS, summary);
  // The 404 allow list takes image delivery as a substring instead (it arrives
  // under more than one shape), so its alternation carries the API paths proper.
  const apiPaths = APP_TRAFFIC_PATHS.filter((p) => !isImageAssetPath(p));
  if (apiPaths.length === 0) {
    throw new Error(
      "APP_TRAFFIC_PATHS 에 이미지 외 서비스 엔드포인트가 없음 — 규칙을 만들 대상이 없습니다.",
    );
  }
  return assembleSurfaceRule(apiPaths, summary);
}

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

const SPEC: Record<Exclude<AssembleKind, EndpointKind>, KindSpec> = {
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
      "알려진 정상 클라이언트(렌더링 엔진을 밝힌 실제 브라우저 · Go 부하생성기 · ELB/Route53/kube 헬스체크 · 이 대시보드의 점검 요청)를 뺀 관측 User-Agent 전부를 패턴화",
      "허용 목록 방식 — 이름 붙은 공격 도구만 막으면 UA 를 위조한 쪽은 그대로 통과한다. \"Mozilla/5.0 (compatible)\" 처럼 아무 엔진도 밝히지 않는 문자열이 대표적",
      "SCANNER·RECON·AUTOMATION 은 도구 이름을, SPOOFED 는 페이로드 형태를, UNKNOWN 은 UA 의 첫 토큰(버전 앞부분)을 매칭 — 버전이 올라가도 계속 걸린다",
      "빈 User-Agent 는 ^$ 로 잡는다. 헤더 자체가 없는 요청은 SingleHeader 문장이 평가되지 않으므로 이 규칙으로는 잡히지 않는다 — 필요하면 별도 규칙이 필요",
      "COMPRESS_WHITE_SPACE 로 공백을 정규화한 뒤 소문자 매칭",
      "단어 경계를 둬서 도구 이름이 다른 토큰 안에 포함된 경우는 매칭하지 않음",
      "적용 전 반드시 시험 탭에서 판정해 볼 것 — 허용 목록에 없는 정상 클라이언트가 이 환경에 있다면 함께 차단된다",
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
function chunkSets(setName: string, patterns: string[]): { name: string; patterns: string[] }[] {
  const chunks: string[][] = [];
  for (let i = 0; i < patterns.length; i += MAX_PATTERNS_PER_SET) {
    chunks.push(patterns.slice(i, i + MAX_PATTERNS_PER_SET));
  }
  return chunks.map((pats, i) => ({
    name: chunks.length === 1 ? setName : `${setName}-${i + 1}`,
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
    `--region ${wafRegion()}`,
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
  if (kind === "query" || kind === "surface") return assembleEndpointRule(kind, summary);
  const spec = SPEC[kind];
  const patterns: string[] = [];
  const evidence: string[] = [];

  if (kind === "path") {
    // Off-surface paths only: anything the environment actually serves, a
    // health check, or image delivery would be a false positive by
    // construction. Image paths in particular are heavy legitimate traffic the
    // score depends on — see isImageAssetPath.
    const seen = new Set<string>();
    for (const p of summary.byPath) {
      if (!p.path.startsWith("/")) continue;
      if (isBenignPath(p.path)) continue;
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
    // Every observed UA that is not a client this environment expects, not just
    // the ones matching a named tool. classifyUa now returns UNKNOWN rather
    // than null for anything unrecognised, so a plain "Mozilla/5.0
    // (compatible)" or a bare curl no longer walks through.
    const seen = new Set<string>();
    for (const ua of summary.byUa) {
      const hit = classifyUa(ua.key);
      if (!hit) continue;
      const fresh = uaPatternsFor(hit.category, hit.label, ua.key);
      if (fresh.length === 0) continue;
      let added = false;
      for (const pattern of fresh) {
        if (seen.has(pattern)) continue;
        seen.add(pattern);
        patterns.push(pattern);
        added = true;
      }
      if (added) {
        evidence.push(
          `"${ua.key}" — ${ua.count}건 · ${hit.category}${
            hit.category === "UNKNOWN" ? " (알려진 정상 클라이언트가 아님)" : ` 시그니처 "${hit.label}"`
          }`,
        );
      }
    }
    if (patterns.length === 0) {
      // "Nothing suspicious was seen" and "nothing was seen" need different
      // answers from the operator, so they get different messages.
      throw new Error(
        summary.byUa.length === 0
          ? "User-Agent 통계가 비어 있습니다 — 관측된 UA 가 하나도 없어 규칙을 만들 수 없습니다. WAF GetSampledRequests 는 규칙에 매칭된 요청만 표본으로 남기므로, 아무것도 매칭하지 않는 WebACL 에서는 항상 0건입니다. WAF 로깅을 켜고 WAF_LOG_GROUP 을 지정하거나, 광범위한 COUNT 규칙을 하나 추가해 표본을 만드세요. (이 환경의 앱 로그에는 user_agent 필드가 없어 대체 수집이 불가능합니다.)"
          : "관측된 User-Agent 가 전부 알려진 정상 클라이언트(렌더링 엔진을 밝힌 브라우저 · Go 부하생성기 · AWS 헬스체크)입니다 — 패턴으로 만들 대상이 없습니다.",
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
  const sets = chunkSets(spec.setName, patterns);
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
