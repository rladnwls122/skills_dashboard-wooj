"use client";

import { useState } from "react";
import {
  assembleRuleAction,
  getCountEvidenceAction,
  getWafSamplesAction,
  updateWafRuleAction,
} from "@/lib/api/dashboard";
import type { CountEvidence } from "@/lib/types";
import type { AssembledRule, AssembleKind, WafPanel, WindowSelection } from "@/lib/types";
import { Card, ErrorNote, Truncate, fmtTs, usePoll, type PollState } from "./shared";
import { ProbePanel } from "./ProbePanel";

// No path rule: an undefined path is already answered with 404 by the ALB, and
// a WAF Block there would turn that 404 into a 403 — the opposite of what the
// task asks for. Path statistics stay on 트래픽 as a watch-only list (04).
const KINDS: { kind: AssembleKind; label: string; sub: string; field: string }[] = [
  {
    kind: "ua",
    label: "스캐너 User-Agent",
    sub: "서비스 경로 AND 공격 도구·위조 UA",
    field: "UriPath + SingleHeader: user-agent",
  },
];

// Builds the scanner User-Agent rule out of what the environment is seeing.
// Nothing here touches the WebACL until a button is pressed: the output is JSON
// to read, apply as Count, then promote by hand.
// Derived from the WebACL, so "추천됨" means exactly "not in the ACL".
function RuleState({ action }: { action: string | null }) {
  const [text, cls] =
    action === null
      ? ["추천됨", "bg-neutral-800 text-neutral-400"]
      : action === "BLOCK"
        ? ["BLOCK", "bg-red-950 text-red-300"]
        : action === "COUNT"
          ? ["COUNT", "bg-amber-950 text-amber-300"]
          : [action, "bg-neutral-800 text-neutral-400"];
  return (
    <span className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${cls}`}>{text}</span>
  );
}

export function UaTab({
  waf,
  window: win,
}: {
  waf: PollState<WafPanel>;
  // Observed paths and UAs are read over the page's shared window, so the
  // assembled rule describes the same span the WAF panel showed.
  window: WindowSelection;
}) {
  // The WebACL is the state: what is applied, at which action, is read back
  // from AWS rather than tracked in a local table that can drift from it (04).
  const samples = usePoll(getWafSamplesAction, 30_000);
  const [rules, setRules] = useState<Partial<Record<AssembleKind, AssembledRule>>>({});
  const [errors, setErrors] = useState<Partial<Record<AssembleKind, string>>>({});
  const [busy, setBusy] = useState<AssembleKind | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  // ARNs the operator pastes back after creating each set, keyed by set name.
  // Until then the rule shows placeholders, because a set name in the ARN field
  // is rejected by AWS rather than quietly matching nothing.
  const [arns, setArns] = useState<Record<string, string>>({});
  const [moving, setMoving] = useState<string | null>(null);
  const [moveError, setMoveError] = useState<string | null>(null);
  const [evidence, setEvidence] = useState<Record<string, CountEvidence | undefined>>({});
  const [evidenceBusy, setEvidenceBusy] = useState<string | null>(null);

  const build = async (kind: AssembleKind): Promise<void> => {
    setBusy(kind);
    const res = await assembleRuleAction(kind, win);
    if (res.ok) {
      setRules((prev) => ({ ...prev, [kind]: res.data }));
      setErrors((prev) => ({ ...prev, [kind]: undefined }));
    } else {
      setErrors((prev) => ({ ...prev, [kind]: res.error }));
      setRules((prev) => ({ ...prev, [kind]: undefined }));
    }
    setBusy(null);
  };

  const copy = async (key: string, text: string): Promise<void> => {
    await navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(null), 1500);
  };

  // Substitutes whatever ARNs have been pasted so far. Anything still missing
  // stays a visible placeholder rather than being silently dropped.
  const withArns = (rule: AssembledRule): string =>
    rule.sets.reduce(
      (json, set) =>
        arns[set.name]?.trim()
          ? json.replaceAll(set.arnPlaceholder, arns[set.name]!.trim())
          : json,
      rule.ruleJson,
    );

  const pendingArns = (rule: AssembledRule): number =>
    rule.sets.filter((set) => !arns[set.name]?.trim()).length;

  // State comes from the WebACL, never from a local flag: the moment someone
  // changes a rule in the console, a local flag would start lying and there is
  // no way to notice mid-match (04).
  const aclAction = (ruleName: string): string | null =>
    waf.data?.acl?.rules.find((r) => r.name === ruleName)?.action ?? null;

  const move = async (rule: AssembledRule, action: "COUNT" | "BLOCK" | null): Promise<void> => {
    setMoving(rule.name);
    setMoveError(null);
    const res = await updateWafRuleAction({ ruleJson: withArns(rule), action, window: win });
    if (!res.ok) setMoveError(res.error);
    else {
      waf.refresh();
      setEvidence((prev) => ({ ...prev, [rule.name]: undefined }));
    }
    setMoving(null);
  };

  const loadEvidence = async (ruleName: string): Promise<void> => {
    setEvidenceBusy(ruleName);
    const res = await getCountEvidenceAction(ruleName, win);
    setEvidence((prev) => ({ ...prev, [ruleName]: res.ok ? res.data : undefined }));
    if (!res.ok) setMoveError(res.error);
    setEvidenceBusy(null);
  };

  return (
    <div className="space-y-3">
      <div className="rounded border border-neutral-800 bg-neutral-900/70 px-3 py-2 text-[11px] text-neutral-400">
        용도별로 <span className="text-neutral-200">정규식 패턴 세트 규칙</span>을 따로 조립합니다.
        패턴은 한 줄에 하나씩(패턴 세트는 줄 단위로 독립 평가), 전부{" "}
        <span className="text-neutral-200">소문자</span>로 작성되며(LOWERCASE 변환이 먼저 적용됨),
        리터럴의 메타문자는 이스케이프되고 RE2 문법만 씁니다.{" "}
        <span className="text-neutral-200">인코딩 우회</span>는 URL_DECODE·HTML_ENTITY_DECODE·
        NORMALIZE_PATH·COMPRESS_WHITE_SPACE 로 먼저 정규화한 뒤 매칭합니다. AWS로 아무것도 보내지
        않으며 WebACL도 건드리지 않습니다.
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-3">
        {KINDS.map((k) => {
          const rule = rules[k.kind];
          const error = errors[k.kind];
          return (
            <Card
              key={k.kind}
              title={k.label}
              right={
                <button
                  type="button"
                  disabled={busy !== null}
                  onClick={() => void build(k.kind)}
                  className="rounded bg-sky-900 px-2 py-0.5 text-[11px] font-semibold text-sky-100 hover:bg-sky-800 disabled:opacity-40"
                >
                  {busy === k.kind ? "조립 중…" : rule ? "다시 조립" : "규칙 조립"}
                </button>
              }
            >
              <div className="mb-2 text-[11px] text-neutral-500">
                {k.sub} · 검사 대상 <span className="text-neutral-300">{k.field}</span>
              </div>

              {/* Stated on screen, not just in the generated JSON: someone
                  reading this over the operator's shoulder has to be able to
                  see why the rule is shaped this way without parsing WAF JSON.
                  The path condition in particular looks redundant until you
                  know it is what keeps a 403 off the undefined paths. */}
              <div className="mb-2 space-y-1 rounded border border-neutral-800 bg-neutral-950 px-2 py-1.5 text-[11px] text-neutral-400">
                <div className="font-semibold text-neutral-300">동작 원리</div>
                <div>
                  두 조건을 <span className="text-neutral-200">모두</span> 만족할 때만 차단합니다
                  (AndStatement).
                </div>
                <div>
                  <span className="text-neutral-200">① 어디로</span> — 요청 경로가 서비스 경로
                  (<span className="font-mono">/v1/user · /v1/product · /v1/stress</span>) 인가.
                  URL_DECODE → NORMALIZE_PATH 로 <span className="font-mono">%2f</span> ·{" "}
                  <span className="font-mono">/./</span> 우회를 편 뒤 비교합니다.
                </div>
                <div>
                  <span className="text-neutral-200">② 누가</span> — User-Agent 가 관측된 공격
                  도구·위조 UA 인가. COMPRESS_WHITE_SPACE → LOWERCASE 로 정규화한 뒤 비교합니다.
                </div>
                <div className="text-neutral-500">
                  경로 조건을 빼면 미지정 경로에도 403 이 나갑니다. 과제 계약은 미지정 경로에 404 를
                  요구하므로 그 자체가 위반입니다 — <span className="text-neutral-300">403 이 정답인
                  곳에서만</span> 차단하려고 조건을 두 개로 나눴습니다.
                </div>
                <div className="text-neutral-500">
                  패턴은 관측된 트래픽에서 만들어집니다. 정상 클라이언트(실제 브라우저 · Go 부하생성기 ·
                  AWS 헬스체크)는 애초에 패턴이 되지 않습니다.
                </div>
              </div>

              <ErrorNote error={error ?? null} />

              {rule && (
                <div className="space-y-3">
                  {/* The endpoint kinds carry the regex inline — no set to
                      create, so the whole ① step disappears. */}
                  {rule.sets.length > 0 && (
                  <div className="text-[11px]">
                    <div className="mb-1 font-semibold text-neutral-300">
                      ① 정규식 패턴 세트 {rule.sets.length > 1 ? `${rule.sets.length}개` : ""} 먼저 생성
                    </div>
                    <div className="mb-1 text-neutral-500">
                      패턴 세트는 규칙과 별개의 리소스입니다. 먼저 만들어 ARN 을 받은 뒤 ②의 규칙이
                      그 ARN 을 참조합니다.
                    </div>
                    {rule.sets.map((set) => (
                      <div key={set.name} className="mb-2 rounded border border-neutral-800 p-2">
                        <div className="mb-1 flex items-center justify-between">
                          <span className="font-mono text-neutral-300">{set.name}</span>
                          <span className="text-neutral-600">정규식 {set.patterns.length}줄</span>
                        </div>
                        <div className="max-h-28 overflow-auto rounded bg-black p-2 font-mono text-[10px] leading-4 text-emerald-300">
                          {set.patterns.map((p, i) => (
                            <div key={i} className="break-all">
                              {p}
                            </div>
                          ))}
                        </div>
                        <div className="mt-1 flex items-center gap-2">
                          <button
                            type="button"
                            onClick={() => void copy(`pat-${set.name}`, set.patterns.join("\n"))}
                            className="rounded bg-neutral-800 px-2 py-0.5 text-neutral-300 hover:bg-neutral-700"
                          >
                            {copied === `pat-${set.name}` ? "복사됨!" : "패턴 복사"}
                          </button>
                          <button
                            type="button"
                            onClick={() => void copy(`cli-${set.name}`, set.createCli)}
                            className="rounded bg-neutral-800 px-2 py-0.5 text-neutral-300 hover:bg-neutral-700"
                          >
                            {copied === `cli-${set.name}` ? "복사됨!" : "생성 CLI 복사"}
                          </button>
                        </div>
                        <input
                          value={arns[set.name] ?? ""}
                          onChange={(e) => setArns((prev) => ({ ...prev, [set.name]: e.target.value }))}
                          placeholder="생성 후 받은 ARN 을 붙여넣으면 ②에 채워집니다"
                          spellCheck={false}
                          className="mt-1 w-full rounded border border-neutral-800 bg-neutral-950 px-1.5 py-0.5 font-mono text-[10px] text-neutral-200"
                        />
                      </div>
                    ))}
                  </div>
                  )}

                  <div className="text-[11px]">
                    <div className="mb-1 font-semibold text-neutral-300">
                      {rule.sets.length > 0 ? "② 규칙 JSON" : "규칙 JSON (그대로 붙여넣기 가능)"}
                    </div>
                    {pendingArns(rule) > 0 && (
                      <div className="mb-1 rounded border border-amber-800/60 bg-amber-950/20 px-2 py-1 text-amber-300">
                        ARN {pendingArns(rule)}개가 아직 자리표시자입니다 — 그대로 붙여넣으면 AWS 가
                        거부합니다. 위에서 세트를 만들고 ARN 을 넣으세요.
                      </div>
                    )}
                    <pre className="max-h-56 overflow-auto rounded bg-black p-2 font-mono text-[10px] leading-4 whitespace-pre-wrap text-neutral-300">
                      {withArns(rule)}
                    </pre>
                    <button
                      type="button"
                      onClick={() => void copy(`rule-${k.kind}`, withArns(rule))}
                      className="mt-1 rounded bg-neutral-800 px-2 py-0.5 text-neutral-300 hover:bg-neutral-700"
                    >
                      {copied === `rule-${k.kind}` ? "복사됨!" : "규칙 JSON 복사"}
                    </button>
                  </div>

                  <div className="text-[11px]">
                    <div className="mb-0.5 text-neutral-500">근거</div>
                    <ul className="space-y-0.5 text-neutral-400">
                      {rule.evidence.map((e, i) => (
                        <li key={i} className="break-all">
                          · {e}
                        </li>
                      ))}
                    </ul>
                  </div>

                  {/* The rule's whole life, on the card that built it. UA goes
                      straight to BLOCK — its patterns are strings the operator
                      just read. SQLi is a fixed signature set that has never met
                      our traffic, so it earns COUNT first (04). */}
                  <div className="rounded border border-neutral-800 bg-neutral-950 p-2 text-[11px]">
                    <div className="mb-1 flex items-center justify-between">
                      <span className="font-mono text-neutral-400">{rule.name}</span>
                      <RuleState action={aclAction(rule.name)} />
                    </div>
                    <div className="flex flex-wrap items-center gap-1.5">
                      {/* COUNT first is always available: it is the only way to
                          see what a rule would have blocked before it blocks
                          anything, and during a match a false positive costs
                          more than a few minutes of counting. */}
                      <button
                        type="button"
                        disabled={moving !== null || pendingArns(rule) > 0}
                        onClick={() => void move(rule, "COUNT")}
                        className="rounded bg-amber-900 px-2 py-0.5 font-semibold text-amber-100 hover:bg-amber-800 disabled:opacity-40"
                      >
                        COUNT 로 올리기
                      </button>
                      <button
                        type="button"
                        disabled={moving !== null || pendingArns(rule) > 0}
                        onClick={() => void move(rule, "BLOCK")}
                        className="rounded bg-red-900 px-2 py-0.5 font-semibold text-red-100 hover:bg-red-800 disabled:opacity-40"
                      >
                        BLOCK 으로 승격
                      </button>
                      <button
                        type="button"
                        disabled={moving !== null || aclAction(rule.name) === null}
                        onClick={() => void move(rule, null)}
                        className="rounded bg-neutral-800 px-2 py-0.5 text-neutral-200 hover:bg-neutral-700 disabled:opacity-40"
                      >
                        내리기
                      </button>
                      {moving === rule.name && <span className="text-neutral-500">적용 중…</span>}
                    </div>
                    <div className="mt-1 text-neutral-500">
                      COUNT 로 올린 뒤 아래 실측을 읽고, 정상 응답 0건일 때 BLOCK 으로 승격하세요.
                      바로 BLOCK 으로 갈 거면 직후에 아래 정상 경로 프로브를 한 번 돌리세요 — 오탐을
                      즉시 알 수 있는 유일한 신호입니다.
                    </div>

                    {aclAction(rule.name) === "COUNT" && (
                      <div className="mt-2 border-t border-neutral-800 pt-2">
                        <button
                          type="button"
                          disabled={evidenceBusy !== null}
                          onClick={() => void loadEvidence(rule.name)}
                          className="rounded bg-neutral-800 px-2 py-0.5 text-neutral-200 hover:bg-neutral-700 disabled:opacity-40"
                        >
                          {evidenceBusy === rule.name ? "집계 중…" : "COUNT 실측 조회"}
                        </button>
                        {evidence[rule.name] && (
                          <div className="mt-1 space-y-1">
                            {/* Three numbers side by side. Unjoinable is not
                                folded into abnormal — POST/PUT carry no
                                requestid on either side, and calling those
                                abnormal would be inventing evidence (07). */}
                            <div className="font-mono text-neutral-200">
                              매칭 {evidence[rule.name]!.total}건 (정상 {evidence[rule.name]!.normal}{" "}
                              · 비정상 {evidence[rule.name]!.abnormal} · 조인 불가{" "}
                              {evidence[rule.name]!.unjoinable})
                            </div>
                            <ul className="space-y-0.5 text-neutral-500">
                              {evidence[rule.name]!.notes.map((n, i) => (
                                <li key={i}>· {n}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  <div className="text-[11px]">
                    <div className="mb-0.5 text-neutral-500">판단 기준</div>
                    <ul className="space-y-0.5 text-neutral-500">
                      {rule.notes.map((n, i) => (
                        <li key={i}>· {n}</li>
                      ))}
                    </ul>
                  </div>

                </div>
              )}

              {!rule && !error && (
                <div className="py-6 text-center text-[11px] text-neutral-600">
                  버튼을 눌러 규칙 조립
                </div>
              )}
            </Card>
          );
        })}
      </div>

      <Card
        title={
          waf.data?.acl
            ? `WebACL 규칙 (${waf.data.acl.name} · 규칙 ${waf.data.acl.ruleCount}개 · WCU ${waf.data.acl.capacityUsed})`
            : "WebACL 규칙"
        }
        right={<ErrorNote error={moveError ?? waf.error} />}
      >
        {waf.data?.acl ? (
          <div className="space-y-0.5 text-[11px]">
            {waf.data.acl.rules.map((r) => (
              <div
                key={r.name}
                className="flex items-center justify-between rounded bg-neutral-950 px-2 py-1"
              >
                <span className="text-neutral-300">{r.name}</span>
                <span className="tabular-nums text-neutral-500">
                  p{r.priority} ·{" "}
                  <span
                    className={
                      r.action === "Block"
                        ? "text-red-400"
                        : r.action === "Count"
                          ? "text-amber-400"
                          : "text-neutral-400"
                    }
                  >
                    {r.action}
                  </span>
                </span>
              </div>
            ))}
            {waf.data.acl.rules.length === 0 && (
              <div className="text-neutral-500">규칙 없음</div>
            )}
          </div>
        ) : (
          <div className="text-[11px] text-red-400">{waf.data?.aclError ?? "WebACL 조회 중…"}</div>
        )}
      </Card>

      {/* COUNT evidence: what a Count rule actually matched. Whether those
          requests were legitimate is what decides promotion. */}
      <Card
        title={`COUNT 실측 증거 (${samples.data?.filter((s) => s.action === "COUNT").length ?? 0}건)`}
        right={
          <button
            type="button"
            onClick={samples.refresh}
            className="rounded bg-neutral-800 px-2 py-0.5 text-[11px] text-neutral-300 hover:bg-neutral-700"
          >
            새로고침
          </button>
        }
      >
        <ErrorNote error={samples.error} />
        <div className="max-h-64 overflow-auto">
          <table className="w-full table-fixed text-left font-mono text-[10px]">
            <thead className="sticky top-0 bg-neutral-900 text-neutral-500">
              <tr>
                {["시각", "IP", "메소드", "경로", "쿼리", "User-Agent", "룰"].map((h) => (
                  <th key={h} className="px-2 py-1 font-medium whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(samples.data ?? [])
                .filter((s) => s.action === "COUNT")
                .map((s, i) => (
                  <tr key={i} className="border-t border-neutral-800 text-neutral-300">
                    <td className="px-2 py-0.5 text-neutral-500">
                      <Truncate text={fmtTs(s.ts)} />
                    </td>
                    <td className="px-2 py-0.5">
                      <Truncate text={s.ip} />
                    </td>
                    <td className="px-2 py-0.5">{s.method}</td>
                    <td className="px-2 py-0.5">
                      <Truncate text={s.path} />
                    </td>
                    <td className="px-2 py-0.5 text-neutral-500">
                      <Truncate text={s.query} />
                    </td>
                    <td className="px-2 py-0.5 text-neutral-500">
                      <Truncate text={s.userAgent} />
                    </td>
                    <td className="px-2 py-0.5 text-neutral-500">
                      <Truncate text={s.rule} />
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
          {(samples.data ?? []).filter((s) => s.action === "COUNT").length === 0 && (
            <div className="p-3 text-center text-[11px] text-neutral-500">
              {samples.loading ? "수집 중…" : "COUNT 로 걸린 요청 없음"}
            </div>
          )}
        </div>
      </Card>

      <ProbePanel />
    </div>
  );
}
