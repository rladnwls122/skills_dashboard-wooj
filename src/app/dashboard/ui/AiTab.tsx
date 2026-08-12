"use client";

import { useState } from "react";
import { assembleRuleAction } from "@/app/actions/dashboard";
import type { AssembledRule, AssembleKind, WindowSelection } from "@/lib/types";
import { Card, ErrorNote } from "./shared";
import { IncidentTab } from "./IncidentTab";

const KINDS: { kind: AssembleKind; label: string; sub: string; field: string }[] = [
  {
    kind: "path",
    label: "의심 경로",
    sub: "관측된 경로 중 서비스 경로 밖의 것",
    field: "UriPath",
  },
  {
    kind: "ua",
    label: "의심 User-Agent",
    sub: "공격 도구·위조로 분류된 UA",
    field: "SingleHeader: user-agent",
  },
  {
    kind: "sqli",
    label: "SQL 인젝션",
    sub: "고정 시그니처 세트 (관측 무관)",
    field: "QueryString",
  },
];

// Generates one regex rule per purpose out of what the environment is seeing,
// and hands the incident snapshot to Amazon Q. Nothing here touches the WebACL:
// the output is JSON to read, test in the 시험 tab, then apply by hand.
export function AiTab({
  onSendToSandbox,
  window: win,
}: {
  onSendToSandbox: (ruleJson: string) => void;
  // Observed paths and UAs are read over the page's shared window, so the
  // assembled rule describes the same span the WAF panel showed.
  window: WindowSelection;
}) {
  const [rules, setRules] = useState<Partial<Record<AssembleKind, AssembledRule>>>({});
  const [errors, setErrors] = useState<Partial<Record<AssembleKind, string>>>({});
  const [busy, setBusy] = useState<AssembleKind | null>(null);
  const [copied, setCopied] = useState<AssembleKind | null>(null);

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

  const copy = async (kind: AssembleKind, text: string): Promise<void> => {
    await navigator.clipboard.writeText(text);
    setCopied(kind);
    setTimeout(() => setCopied(null), 1500);
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

              <ErrorNote error={error ?? null} />

              {rule && (
                <div className="space-y-2">
                  <div className="text-[11px]">
                    <div className="mb-0.5 text-neutral-500">패턴 {rule.patterns.length}줄</div>
                    <div className="max-h-32 overflow-auto rounded bg-black p-2 font-mono text-[10px] leading-4 text-emerald-300">
                      {rule.patterns.map((p, i) => (
                        <div key={i} className="break-all">
                          {p}
                        </div>
                      ))}
                    </div>
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

                  <div className="text-[11px]">
                    <div className="mb-0.5 text-neutral-500">판단 기준</div>
                    <ul className="space-y-0.5 text-neutral-500">
                      {rule.notes.map((n, i) => (
                        <li key={i}>· {n}</li>
                      ))}
                    </ul>
                  </div>

                  <details className="text-[11px]">
                    <summary className="cursor-pointer text-neutral-400 hover:text-neutral-200">
                      규칙 JSON 보기
                    </summary>
                    <pre className="mt-1 max-h-56 overflow-auto rounded bg-black p-2 font-mono text-[10px] leading-4 whitespace-pre-wrap text-neutral-300">
                      {rule.ruleJson}
                    </pre>
                  </details>

                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={() => onSendToSandbox(rule.ruleJson)}
                      className="rounded bg-neutral-800 px-2 py-0.5 text-[11px] text-neutral-200 hover:bg-neutral-700"
                    >
                      시험 탭으로 보내기
                    </button>
                    <button
                      type="button"
                      onClick={() => void copy(k.kind, rule.ruleJson)}
                      className="rounded bg-neutral-800 px-2 py-0.5 text-[11px] text-neutral-300 hover:bg-neutral-700"
                    >
                      {copied === k.kind ? "복사됨!" : "복사"}
                    </button>
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

      <IncidentTab />
    </div>
  );
}
