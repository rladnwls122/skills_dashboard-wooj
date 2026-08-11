"use client";

import { Fragment, useEffect, useState } from "react";
import {
  getDefaultTestRequestsAction,
  getMaliciousExampleRequestsAction,
  testRuleJsonAction,
} from "@/app/actions/dashboard";
import type { RuleTestResult, TestRequest, WafPanel } from "@/lib/types";
import { Card, ErrorNote, SectionLoading, Truncate, type PollState } from "./shared";

const PLACEHOLDER = `{
  "Name": "block-wp-login",
  "Priority": 100,
  "Statement": {
    "ByteMatchStatement": {
      "SearchString": "/wp-login",
      "FieldToMatch": { "UriPath": {} },
      "TextTransformations": [{ "Priority": 0, "Type": "LOWERCASE" }],
      "PositionalConstraint": "STARTS_WITH"
    }
  },
  "Action": { "Block": {} }
}

// 규칙 하나 / Rule 배열 / WebACL JSON 전체 / Statement 본문 모두 가능.
// 콘솔에서 규칙을 하나씩 복사해 { … }{ … } 로 이어붙여도 그대로 읽음.
// 주석(// , /* */)과 마지막 쉼표도 허용.
// IP 세트·정규식 세트를 참조하는 규칙은 최상위에 내용을 같이 넣으면 평가됨:
// { "IPSets": { "office-ips": ["10.0.0.0/8"] }, "Rules": [ ... ] }`;

const VERDICT_STYLE: Record<RuleTestResult["verdict"], { label: string; cls: string }> = {
  SAFE: { label: "안전 — 정상 요청 전부 통과", cls: "border-emerald-800 bg-emerald-950/40 text-emerald-300" },
  FALSE_POSITIVE_RISK: {
    label: "오탐 위험 — 정상 요청이 차단됨",
    cls: "border-red-800 bg-red-950/40 text-red-300",
  },
  INCONCLUSIVE: {
    label: "판정 불가 — 로컬에서 평가할 수 없는 문법 포함",
    cls: "border-amber-700 bg-amber-950/40 text-amber-300",
  },
};

const OUTCOME_STYLE: Record<string, { label: string; cls: string }> = {
  PASS: { label: "통과", cls: "text-emerald-400" },
  BLOCKED: { label: "차단", cls: "text-red-400 font-bold" },
  COUNTED: { label: "카운트만", cls: "text-amber-400" },
  CAUGHT: { label: "정탐(차단)", cls: "text-emerald-400 font-bold" },
  CHALLENGED: { label: "CAPTCHA/Challenge", cls: "text-sky-400" },
  MATCHED: { label: "매칭(Action 없음)", cls: "text-neutral-300" },
  UNKNOWN: { label: "판정 불가", cls: "text-neutral-400" },
};

const FIELDS = [
  { key: "method", label: "메소드", width: "w-16" },
  { key: "path", label: "경로", width: "w-40" },
  { key: "query", label: "쿼리", width: "w-32" },
  { key: "userAgent", label: "User-Agent", width: "w-48" },
  { key: "ip", label: "IP", width: "w-28" },
] as const;

// "Name: value" lines <-> the header map the evaluator inspects.
function headersToText(headers: Record<string, string> | undefined): string {
  return Object.entries(headers ?? {})
    .map(([k, v]) => `${k}: ${v}`)
    .join("\n");
}

function textToHeaders(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const t = line.trim();
    if (t.length === 0) continue;
    const colon = t.indexOf(":");
    if (colon <= 0) continue;
    out[t.slice(0, colon).trim()] = t.slice(colon + 1).trim();
  }
  return out;
}

export function SandboxTab({ waf }: { waf: PollState<WafPanel> }) {
  const [ruleJson, setRuleJson] = useState("");
  const [requests, setRequests] = useState<TestRequest[] | null>(null);
  const [headerText, setHeaderText] = useState<Record<string, string>>({});
  const [expanded, setExpanded] = useState<string | null>(null);
  const [result, setResult] = useState<RuleTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const seedHeaderText = (rows: TestRequest[]): void => {
    setHeaderText((prev) => {
      const next = { ...prev };
      for (const r of rows) next[r.id] ??= headersToText(r.headers);
      return next;
    });
  };

  useEffect(() => {
    void (async () => {
      const res = await getDefaultTestRequestsAction();
      if (res.ok) {
        setRequests(res.data);
        seedHeaderText(res.data);
      } else setError(res.error);
    })();
  }, []);

  const run = async (): Promise<void> => {
    if (!requests) return;
    setBusy(true);
    setResult(null);
    const res = await testRuleJsonAction({ ruleJson, requests });
    if (res.ok) {
      setResult(res.data);
      setError(null);
    } else {
      setError(res.error);
    }
    setBusy(false);
  };

  const patch = (id: string, change: Partial<TestRequest>): void => {
    setRequests((prev) => (prev ?? []).map((r) => (r.id === id ? { ...r, ...change } : r)));
  };

  const editField = (id: string, key: (typeof FIELDS)[number]["key"], value: string): void => {
    patch(id, { [key]: value } as Partial<TestRequest>);
  };

  const editHeaders = (id: string, text: string): void => {
    setHeaderText((prev) => ({ ...prev, [id]: text }));
    patch(id, { headers: textToHeaders(text) });
  };

  const addRow = (): void => {
    const id = `custom-${Date.now()}`;
    setRequests((prev) => [
      ...(prev ?? []),
      {
        id,
        method: "GET",
        path: "/",
        query: "",
        userAgent: "Mozilla/5.0",
        ip: "10.0.2.1",
        country: "KR",
        benign: true,
        headers: {},
        body: "",
        labels: [],
      },
    ]);
    setHeaderText((prev) => ({ ...prev, [id]: "" }));
    setExpanded(id);
  };

  const addMalicious = async (): Promise<void> => {
    const res = await getMaliciousExampleRequestsAction();
    if (!res.ok) { setError(res.error); return; }
    setRequests((prev) => {
      const have = new Set((prev ?? []).map((r) => r.id));
      const fresh = res.data.filter((r) => !have.has(r.id));
      seedHeaderText(fresh);
      return [...(prev ?? []), ...fresh];
    });
  };

  const removeRow = (id: string): void => {
    setRequests((prev) => (prev ?? []).filter((r) => r.id !== id));
  };

  const recs = waf.data?.recommendations ?? [];
  const rowById = new Map((requests ?? []).map((r) => [r.id, r]));

  return (
    <div className="space-y-3">
      <div className="rounded border border-neutral-800 bg-neutral-900/70 px-3 py-2 text-[11px] text-neutral-400">
        붙여넣은 규칙을 아래 요청들에 대해 <span className="text-neutral-200">로컬에서만</span> 평가합니다.
        AWS로 아무것도 전송하지 않고 WebACL도 건드리지 않습니다. 규칙 하나뿐 아니라{" "}
        <span className="text-neutral-200">Rule 배열·WebACL JSON 전체</span>, 그리고{" "}
        <span className="text-neutral-200">규칙 여러 개를 그냥 이어붙인 형태(</span>
        <code className="text-neutral-200">{"{…}{…}"}</code>
        <span className="text-neutral-200">)</span>도 그대로 붙여넣을 수 있고,
        여러 규칙은 Priority 순서대로 평가해 어느 규칙이 결정했는지 표시합니다. 관리형 규칙 그룹과
        SQLi/XSS 문장은 <span className="text-neutral-200">로컬 근사</span>로 평가되며,
        AWS 내부 데이터가 필요한 항목만 <span className="text-neutral-200">판정 불가</span>로 남습니다.
      </div>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card
          title="규칙 JSON"
          right={
            recs.length > 0 ? (
              <select
                defaultValue=""
                onChange={(e) => {
                  const rec = recs.find((r) => r.id === e.target.value);
                  if (rec) setRuleJson(rec.ruleJson);
                }}
                className="rounded border border-neutral-700 bg-neutral-900 px-1.5 py-0.5 text-[11px] text-neutral-300"
              >
                <option value="">추천 규칙 불러오기…</option>
                {recs.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name} — {r.targetPattern.slice(0, 40)}
                  </option>
                ))}
              </select>
            ) : null
          }
        >
          <textarea
            value={ruleJson}
            onChange={(e) => setRuleJson(e.target.value)}
            placeholder={PLACEHOLDER}
            spellCheck={false}
            rows={16}
            className="w-full resize-y rounded border border-neutral-800 bg-neutral-950 p-2 font-mono text-[10px] text-neutral-200"
          />
          <div className="mt-2 flex items-center gap-2">
            <button
              type="button"
              onClick={() => void run()}
              disabled={busy || !ruleJson.trim() || !requests}
              className="rounded bg-sky-900 px-3 py-1 text-[11px] font-semibold text-sky-100 hover:bg-sky-800 disabled:opacity-40"
            >
              {busy ? "평가 중…" : "시험 실행"}
            </button>
            <ErrorNote error={error} />
          </div>
        </Card>

        <Card
          title={`정상 요청 (${requests?.length ?? 0})`}
          right={
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={addRow}
                className="rounded bg-neutral-800 px-2 py-0.5 text-[11px] text-neutral-300 hover:bg-neutral-700"
              >
                + 행 추가
              </button>
              <button
                type="button"
                onClick={() => void addMalicious()}
                className="rounded bg-red-950 px-2 py-0.5 text-[11px] text-red-300 hover:bg-red-900"
              >
                + 악성 예시
              </button>
            </div>
          }
        >
          {requests === null ? (
            <SectionLoading />
          ) : (
            <div className="max-h-80 overflow-auto">
              <table className="w-full text-left font-mono text-[10px]">
                <thead className="sticky top-0 bg-neutral-900 text-neutral-500">
                  <tr>
                    <th className="px-1 py-1" />
                    {FIELDS.map((f) => (
                      <th key={f.key} className="px-1 py-1 font-medium">
                        {f.label}
                      </th>
                    ))}
                    <th className="px-1 py-1" />
                  </tr>
                </thead>
                <tbody>
                  {requests.map((r) => (
                    <Fragment key={r.id}>
                      <tr
                        className={`border-t border-neutral-800 ${r.benign === false ? "bg-red-950/30" : ""}`}
                      >
                        <td className="px-1 py-0.5">
                          <button
                            type="button"
                            onClick={() => setExpanded((cur) => (cur === r.id ? null : r.id))}
                            aria-label={`${r.id} 헤더·바디 편집`}
                            aria-expanded={expanded === r.id}
                            className="rounded px-1 text-neutral-500 hover:bg-neutral-800 hover:text-neutral-200"
                          >
                            {expanded === r.id ? "▾" : "▸"}
                          </button>
                        </td>
                        {FIELDS.map((f) => (
                          <td key={f.key} className="px-1 py-0.5">
                            <input
                              value={r[f.key]}
                              onChange={(e) => editField(r.id, f.key, e.target.value)}
                              className={`${f.width} rounded border border-neutral-800 bg-neutral-950 px-1 py-0.5 text-neutral-200`}
                            />
                          </td>
                        ))}
                        <td className="px-1 py-0.5">
                          <button
                            type="button"
                            onClick={() => removeRow(r.id)}
                            aria-label={`${r.id} 삭제`}
                            className="rounded px-1 text-neutral-500 hover:bg-neutral-800 hover:text-neutral-200"
                          >
                            ✕
                          </button>
                        </td>
                      </tr>
                      {expanded === r.id && (
                        <tr className="border-t border-neutral-900 bg-neutral-950/60">
                          <td />
                          <td colSpan={FIELDS.length + 1} className="px-1 py-1">
                            <div className="grid grid-cols-1 gap-2 md:grid-cols-3">
                              <label className="block">
                                <span className="mb-0.5 block text-neutral-500">
                                  헤더 (한 줄에 &quot;이름: 값&quot;)
                                </span>
                                <textarea
                                  value={headerText[r.id] ?? ""}
                                  onChange={(e) => editHeaders(r.id, e.target.value)}
                                  rows={3}
                                  spellCheck={false}
                                  placeholder={"cookie: session=abc\nx-forwarded-for: 203.0.113.9"}
                                  className="w-full resize-y rounded border border-neutral-800 bg-neutral-950 px-1 py-0.5 text-neutral-200"
                                />
                              </label>
                              <label className="block">
                                <span className="mb-0.5 block text-neutral-500">바디</span>
                                <textarea
                                  value={r.body ?? ""}
                                  onChange={(e) => patch(r.id, { body: e.target.value })}
                                  rows={3}
                                  spellCheck={false}
                                  placeholder={'{"name":"kim"}'}
                                  className="w-full resize-y rounded border border-neutral-800 bg-neutral-950 px-1 py-0.5 text-neutral-200"
                                />
                              </label>
                              <div className="space-y-1">
                                <label className="block">
                                  <span className="mb-0.5 block text-neutral-500">국가 코드</span>
                                  <input
                                    value={r.country}
                                    onChange={(e) => patch(r.id, { country: e.target.value })}
                                    className="w-20 rounded border border-neutral-800 bg-neutral-950 px-1 py-0.5 text-neutral-200"
                                  />
                                </label>
                                <label className="block">
                                  <span className="mb-0.5 block text-neutral-500">
                                    라벨 (쉼표 구분, LabelMatch용)
                                  </span>
                                  <input
                                    value={(r.labels ?? []).join(",")}
                                    onChange={(e) =>
                                      patch(r.id, {
                                        labels: e.target.value
                                          .split(",")
                                          .map((s) => s.trim())
                                          .filter((s) => s.length > 0),
                                      })
                                    }
                                    className="w-full rounded border border-neutral-800 bg-neutral-950 px-1 py-0.5 text-neutral-200"
                                  />
                                </label>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      {result && (
        <Card
          title={
            result.ruleCount > 1
              ? `결과 — ${result.ruleName} (Priority 순 평가)`
              : `결과 — ${result.ruleName} (Action: ${result.action})`
          }
        >
          <div
            className={`mb-2 rounded border px-3 py-2 text-[12px] font-semibold ${VERDICT_STYLE[result.verdict].cls}`}
          >
            {VERDICT_STYLE[result.verdict].label}
          </div>
          <div className="mb-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px]">
            <span className="text-emerald-400">통과 {result.passed}</span>
            <span className="text-red-400">차단 {result.blocked}</span>
            <span className="text-amber-400">카운트만 {result.counted}</span>
            <span className="text-emerald-400">정탐 {result.caught}</span>
            <span className="text-red-300">미탐 {result.missed}</span>
            {result.challenged > 0 && (
              <span className="text-sky-400">CAPTCHA/Challenge {result.challenged}</span>
            )}
            {result.matched > 0 && (
              <span className="text-neutral-300">Action 없는 매칭 {result.matched}</span>
            )}
            <span className="text-neutral-400">판정 불가 {result.unknown}</span>
          </div>
          {result.approximated.length > 0 && (
            <div className="mb-2 rounded border border-amber-800/60 bg-amber-950/20 px-2 py-1 text-[11px] text-amber-300">
              근사 평가: {result.approximated.join(", ")} — AWS 내부 구현과 다를 수 있으니 COUNT로 확인
            </div>
          )}
          <table className="w-full text-left font-mono text-[10px]">
            <thead className="text-neutral-500">
              <tr>
                {["요청", "경로", "User-Agent", "결과", "결정 규칙", "이유"].map((h) => (
                  <th key={h} className="px-2 py-1 font-medium">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {result.rows.map((row) => {
                const req = rowById.get(row.requestId);
                const style = OUTCOME_STYLE[row.outcome] ?? OUTCOME_STYLE["UNKNOWN"];
                return (
                  <tr key={row.requestId} className="border-t border-neutral-800 text-neutral-300">
                    <td className="px-2 py-0.5 text-neutral-500">{row.requestId}</td>
                    <td className="px-2 py-0.5">
                      <Truncate text={req?.path ?? ""} className="max-w-40" />
                    </td>
                    <td className="px-2 py-0.5 text-neutral-500">
                      <Truncate text={req?.userAgent ?? ""} className="max-w-40" />
                    </td>
                    <td className={`px-2 py-0.5 ${style?.cls ?? ""}`}>{style?.label ?? row.outcome}</td>
                    <td className="px-2 py-0.5 text-neutral-500">
                      <Truncate text={row.ruleName ?? "—"} className="max-w-32" />
                    </td>
                    <td className="px-2 py-0.5 text-neutral-500">{row.reason}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {result.notes.length > 0 && (
            <ul className="mt-2 space-y-0.5 text-[11px] text-neutral-500">
              {result.notes.map((n, i) => (
                <li key={i}>· {n}</li>
              ))}
            </ul>
          )}
        </Card>
      )}
    </div>
  );
}
