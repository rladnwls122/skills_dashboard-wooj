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

import { ENV, RULE_SCOPE_PATHS, wafRegion } from "./config";
import { classifyUa, spoofedUaPatterns, type ThreatCategory } from "./threatsig";
import type { AssembledRule, AssembleKind, HttpSummary } from "@/lib/types";

// Fixed AWS WAF quotas (not adjustable). Exceeding either means the pattern set
// is rejected at creation time, so the assembler enforces them here rather than
// handing over JSON that only fails once it reaches AWS.
// https://docs.aws.amazon.com/waf/latest/developerguide/limits.html
export const MAX_PATTERNS_PER_SET = 10;
export const MAX_PATTERN_CHARS = 200;

// How much allowed service traffic makes a User-Agent untouchable. One allowed
// request could be a probe that slipped through a gap between rules; a hundred
// is a client the environment is being served by, and blocking it is an outage.
export const UA_ALLOWED_LIMIT = 100;

// Escapes every regex metacharacter so a literal is matched as text.
export function escapeLiteral(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&");
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
//
// Every signature here has to survive one question: can this appear in text a
// person would legitimately send? The loose ones were removed after a rule
// built from them blocked 12,024 consecutive PUT /v1/product requests — the
// whole product-update workload, from every client including the load
// generator — because the shapes below matched ordinary product text:
//
//   `select\s+.+\s+from\s+`  → ".+" spans anything, so "select the small one
//                              from the list" in a description matches.
//   `--\s*$`                 → a body that happens to end in a dash pair.
//   `/\*.*\*/`               → CSS/JS text quoted inside a payload.
//   `sleep\s*\(\d+\)`        → product copy: "sleep (8 hours)".
//
// What is left needs SQL structure, not a SQL word: an injection keyword pair,
// a comparison of two constants, a comment marker right after a quote. The
// benign corpus in scripts/ruleassemble.test.mjs is the regression test — every
// pattern is checked against real request text from this scenario.
export const SQLI_PATTERNS = [
  // Keyword pairs that only occur together in a statement. The gap between
  // SELECT and FROM may not cross a quote or a brace: "select comfort
  // pillow","description":"chosen from …" is a product, not a query, and the
  // punctuation is what says so.
  "union\\s+(all\\s+)?select|\\bselect\\b[^\"'{};]{0,60}?\\bfrom\\s+[a-z_]",
  // INSERT needs its table and an opening paren or VALUES — "insert into your
  // summer wardrobe" is ad copy and reaches neither.
  "insert\\s+into\\s+[a-z_][a-z0-9_.]*\\s*(\\(|values\\b)|drop\\s+table\\s+[a-z_]|;\\s*(select|insert|update|delete|drop)\\b",
  // Tautologies. Two constants compared is the shape; prose does not do it.
  "\\bor\\s+1\\s*=\\s*1\\b|\\bor\\s+'[^']*'\\s*=\\s*'|(^|[^a-z])(and|or)\\s+\\d+\\s*=\\s*\\d+",
  // Time-based probes, but only where the call follows injection punctuation —
  // "sleep(8)" on its own is a mattress, not an attack.
  "['\");]\\s*(sleep|benchmark|pg_sleep)\\s*\\(|waitfor\\s+delay\\s+'",
  "load_file\\s*\\(|into\\s+outfile\\s+",
  "information_schema",
  // A comment marker that terminates a quoted value — the classic tail of an
  // injected string. Not a bare "--", which is ordinary punctuation.
  "['\")]\\s*(--|#)\\s*$|['\")]\\s*/\\*",
] as const;

interface KindSpec {
  name: string;
  setName: string;
  // Distinct per kind so both rule cards can be added to one WebACL.
  priority: number;
  // Every field the same pattern set is applied to. More than one produces an
  // OrStatement — a query-string injection and a request-body injection are the
  // same attack and deserve the same rule.
  fields: Record<string, unknown>[];
  // Applied in Priority order before the match.
  transforms: string[];
  notes: string[];
}

const SPEC: Record<AssembleKind, KindSpec> = {
  ua: {
    name: "dash-regex-ua",
    setName: "dash-threat-uas",
    priority: 101,
    fields: [{ SingleHeader: { Name: "user-agent" } }],
    transforms: ["URL_DECODE", "COMPRESS_WHITE_SPACE", "LOWERCASE"],
    notes: [
      "알려진 정상 클라이언트(렌더링 엔진을 밝힌 실제 브라우저 · Go 부하생성기 · ELB/Route53/kube 헬스체크 · 이 대시보드의 점검 요청)를 뺀 관측 User-Agent 전부를 패턴화",
      "허용 목록 방식 — 이름 붙은 공격 도구만 막으면 UA 를 위조한 쪽은 그대로 통과한다. \"Mozilla/5.0 (compatible)\" 처럼 아무 엔진도 밝히지 않는 문자열이 대표적",
      "SCANNER·RECON·AUTOMATION 은 도구 이름을, SPOOFED 는 페이로드 형태를, UNKNOWN 은 UA 의 첫 토큰(버전 앞부분)을 매칭 — 버전이 올라가도 계속 걸린다",
      "빈 User-Agent 는 ^$ 로 잡는다. 헤더 자체가 없는 요청은 SingleHeader 문장이 평가되지 않으므로 이 규칙으로는 잡히지 않는다 — 필요하면 별도 규칙이 필요",
      "COMPRESS_WHITE_SPACE 로 공백을 정규화한 뒤 소문자 매칭",
      "단어 경계를 둬서 도구 이름이 다른 토큰 안에 포함된 경우는 매칭하지 않음",
      "적용은 반드시 Count 부터 — 허용 목록에 없는 정상 클라이언트가 이 환경에 있다면 함께 차단된다",
    ],
  },
  sqli: {
    name: "dash-regex-sqli",
    setName: "dash-sqli-signatures",
    priority: 102,
    // Query string only. Inspecting the body as well is what turned this rule
    // into an outage: the observed injections all arrive in the query string
    // (`id=1' OR '1'='1`), while the request body is where the scenario's
    // legitimate PUT /v1/product payload lives — product text that a loose
    // signature will eventually match. The body is the higher-risk field and
    // the lower-value one here, so it is out.
    fields: [{ QueryString: {} }],
    transforms: ["URL_DECODE", "HTML_ENTITY_DECODE", "COMPRESS_WHITE_SPACE", "LOWERCASE"],
    notes: [
      "관측과 무관한 고정 시그니처 세트 — 트래픽이 조용해도 항상 같은 패턴을 냄",
      "쿼리 문자열만 검사한다 — 요청 본문은 검사하지 않음. 본문 검사를 켰던 규칙이 정상 PUT /v1/product 12,024건을 전부 차단한 사고가 있었고(모든 UA 균등, 통과 0건), 관측된 주입은 전부 쿼리 문자열에 있었다",
      "URL_DECODE + HTML_ENTITY_DECODE 로 %20·&#x2f; 인코딩 우회를 먼저 풀고, COMPRESS_WHITE_SPACE 로 공백 삽입 우회를 정규화",
      "시그니처는 SQL 단어가 아니라 SQL 구조를 요구한다 — 키워드 쌍(union select, from <테이블>), 상수 비교(or 1=1), 따옴표 뒤 주석(' --). 정상 텍스트에 섞인 select·sleep·-- 는 매칭하지 않음",
      "AWS 관리형 SQLi 규칙 그룹(SQLi_QUERYARGUMENTS)이 이미 같은 트래픽을 잡고 있음 — 중복이면 이 규칙 없이도 차단된다. COUNT 로 겹침을 먼저 확인할 것",
    ],
  },
};

// A regex pattern set is its own AWS resource: it is created first, gets an
// ARN, and the rule references that ARN. So the two artefacts are produced
// separately — the set contents to create, and the rule that points at them.
//
// The rule handed to the console therefore carries an ARN placeholder, not the
// set name: a name in the ARN field is rejected at creation time, and would
// have failed only after the operator pasted it.
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
    `--region ${wafRegion()}`,
    `--regular-expression-list '${list}'`,
  ].join(" ");
}

// The path scope-down every rule is wrapped in.
//
// The WAF sits in front of the ALB. Without this, a malicious-UA request to an
// undefined path is cut with 403 before the ALB can answer it with the 404 the
// task requires, and `Exception Handling` drops for a request nobody meant to
// touch. So detection is AND'ed with "the URI is one we serve" (the API surface
// plus the health check) — the rule can only ever fire inside the surface we
// own. The health check is inside that surface on purpose: a scanner probing it
// should be blocked like any other, and the probes that must never be blocked
// (ELB-HealthChecker, kube-probe) are excluded by UA, not by path.
export function pathScopeStatement(): Record<string, unknown> {
  const transforms = [
    { Priority: 0, Type: "URL_DECODE" },
    { Priority: 1, Type: "NORMALIZE_PATH" },
    { Priority: 2, Type: "LOWERCASE" },
  ];
  const matches = RULE_SCOPE_PATHS.map((p) => ({
    ByteMatchStatement: {
      SearchString: p.toLowerCase(),
      FieldToMatch: { UriPath: {} },
      TextTransformations: transforms,
      PositionalConstraint: "STARTS_WITH",
    },
  }));
  return matches.length === 1 ? matches[0]! : { OrStatement: { Statements: matches } };
}

// Does this statement narrow a rule to the served API paths?
//
// Accepts a bare ByteMatch/RegexPatternSetReference on UriPath, or an Or of
// them. A ByteMatch has to name a path we actually serve — a scope-down onto
// some other prefix is not a scope-down, it is a different rule.
function isPathScope(stmt: unknown): boolean {
  if (!stmt || typeof stmt !== "object") return false;
  const s = stmt as Record<string, any>;

  if (s.OrStatement?.Statements) {
    const kids = s.OrStatement.Statements as unknown[];
    return kids.length > 0 && kids.every(isPathScope);
  }
  if (s.ByteMatchStatement?.FieldToMatch?.UriPath) {
    const needle = String(s.ByteMatchStatement.SearchString ?? "").toLowerCase();
    return RULE_SCOPE_PATHS.some((p) => needle.startsWith(p.toLowerCase()));
  }
  // The set's contents live in AWS, not in the JSON, so this is taken at its
  // word — the operator wrote the set and can see what is in it.
  if (s.RegexPatternSetReferenceStatement?.FieldToMatch?.UriPath) return true;
  return false;
}

// The gate both paths into the WebACL pass through: the assembler's own output
// and anything an operator pastes. Returns null when the rule is acceptable,
// or the reason it is refused.
export function scopeDownRefusal(rule: unknown): string | null {
  if (!rule || typeof rule !== "object") return "규칙 JSON 을 읽을 수 없습니다.";
  const stmt = (rule as Record<string, any>).Statement;
  if (!stmt) return "규칙에 Statement 가 없습니다.";
  const and = (stmt as Record<string, any>).AndStatement?.Statements as unknown[] | undefined;
  if (!and || and.length < 2) {
    return `경로 스코프다운이 없습니다 — AndStatement 로 제공 API 경로(${RULE_SCOPE_PATHS.join(", ")}) 조건과 묶여야 합니다. 스코프다운 없이 올리면 미지정 경로가 404 대신 403 을 받아 Exception Handling 이 깨집니다.`;
  }
  if (!and.some(isPathScope)) {
    return `AndStatement 안에 제공 API 경로(${RULE_SCOPE_PATHS.join(", ")}) 조건이 없습니다.`;
  }
  return null;
}

// `arnFor` decides what goes in the ARN field — a placeholder until the
// operator creates the set and pastes the real ARN back.
function buildRule(
  spec: KindSpec,
  sets: { name: string; patterns: string[] }[],
  action: "BLOCK" | "COUNT",
  arnFor: (setName: string) => string,
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
  const detection = refs.length === 1 ? refs[0]! : { OrStatement: { Statements: refs } };

  const rule = {
    Name: spec.name,
    Priority: spec.priority,
    Statement: { AndStatement: { Statements: [pathScopeStatement(), detection] } },
    Action: action === "BLOCK" ? { Block: {} } : { Count: {} },
    VisibilityConfig: {
      SampledRequestsEnabled: true,
      CloudWatchMetricsEnabled: true,
      MetricName: spec.name,
    },
  };

  return JSON.stringify(rule, null, 2);
}

// Builds the rule for one purpose. `summary` is only read for the observed
// kinds; "sqli" ignores it entirely.
export function assembleRule(kind: AssembleKind, summary: HttpSummary): AssembledRule {
  const spec = SPEC[kind];
  const patterns: string[] = [];
  const evidence: string[] = [];
  // Candidates the gate below refused, kept so the operator sees what was left
  // out and why — a rule that silently drops a UA reads as a missed detection.
  const skipped: string[] = [];

  if (kind === "ua") {
    // Every observed UA that is not a client this environment expects — minus
    // the ones the measurement says are carrying live service traffic.
    const seen = new Set<string>();
    const allowedByUa = new Map(summary.uaActions.map((u) => [u.key, u]));
    for (const ua of summary.byUa) {
      const hit = classifyUa(ua.key);
      if (!hit) continue;

      // The false-positive gate. A client the WebACL is currently allowing
      // through on /v1/* is serving the scenario's own traffic, whatever its
      // name looks like: here the load generator rotates curl, wget,
      // python-requests, okhttp, axios, Postman and Apache-HttpClient, each
      // with thousands of allowed requests, and a UA rule built from the name
      // alone would have blocked every one of them. Blocking is reserved for
      // clients whose service traffic is not being served — measured per
      // assembly, never assumed.
      const seenTraffic = allowedByUa.get(ua.key);
      if (seenTraffic && seenTraffic.allowed >= UA_ALLOWED_LIMIT) {
        skipped.push(
          `"${ua.key}" — ${hit.category}${hit.category === "UNKNOWN" ? "" : ` "${hit.label}"`} 이지만 /v1/* 정상 통과 ${seenTraffic.allowed}건 · 차단 ${seenTraffic.blocked}건 → 차단 대상에서 제외 (오탐 위험)`,
        );
        continue;
      }

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
        const traffic = seenTraffic
          ? ` · /v1/* 통과 ${seenTraffic.allowed}건 · 차단 ${seenTraffic.blocked}건`
          : "";
        evidence.push(
          `"${ua.key}" — ${ua.count}건 · ${hit.category}${
            hit.category === "UNKNOWN" ? " (알려진 정상 클라이언트가 아님)" : ` 시그니처 "${hit.label}"`
          }${traffic}`,
        );
      }
    }
    if (patterns.length === 0 && skipped.length > 0) {
      throw new Error(
        `관측된 User-Agent 가 전부 /v1/* 정상 통과 트래픽을 가지고 있어 차단 패턴을 만들지 않았습니다 — 지금 규칙을 올리면 정상 요청이 함께 막힙니다. 제외 내역: ${skipped.join(" / ")}`,
      );
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
  const sets = chunkSets(spec, patterns);
  const setCount = sets.length;
  const capNote =
    setCount > 1
      ? [
          `패턴 ${patterns.length}개를 세트 ${setCount}개로 나눠 담음 — 세트당 정규식 ${MAX_PATTERNS_PER_SET}개가 AWS 고정 한도라, 나머지는 버리지 않고 세트를 늘려 OrStatement 로 묶었습니다. 콘솔에서는 정규식 패턴 세트를 ${setCount}개 만들고 각 ARN 을 넣으세요 (계정·리전당 패턴 세트 10개가 기본 한도, 상향 요청 가능).`,
        ]
      : [];

  // SQLi is a fixed signature set that has never seen our traffic, so it goes
  // up as COUNT and is promoted on measurement. UA patterns are built from
  // strings the operator just read on screen, so a COUNT round would only delay
  // the block (04).
  const action = kind === "sqli" ? "COUNT" : "BLOCK";

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
    ruleJson: buildRule(spec, sets, action, placeholder),
    // The data this rule was written from, named on the artefact itself: a rule
    // is only as current as the summary behind it, and the summary says whether
    // it was read live or served from a cache.
    evidence: kind === "ua" ? [`관측 출처: ${summary.source}`, ...evidence] : evidence,
    notes: [
      ...spec.notes,
      ...capNote,
      ...(skipped.length > 0
        ? [
            `오탐 가드로 제외된 후보 ${skipped.length}건 — /v1/* 에서 정상 통과 중인 클라이언트는 이름이 도구처럼 보여도 패턴화하지 않습니다: ${skipped.join(" / ")}`,
          ]
        : []),
      "제공 API 경로 조건과 AND 로 묶여 있음 — 미지정 경로 요청은 이 규칙에 걸리지 않고 ALB 의 404 로 간다",
      action === "COUNT"
        ? "Action 은 COUNT — 매칭 건수와 앱 응답을 확인한 뒤 Block 으로 승격하세요."
        : "Action 은 Block — 올린 직후 정상 경로 프로브를 한 번 돌려 200 인지 확인하세요.",
    ],
  };
}
