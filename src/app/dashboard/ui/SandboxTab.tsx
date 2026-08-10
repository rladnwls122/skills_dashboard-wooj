"use client";

import { useEffect, useState } from "react";
import { getDefaultTestRequestsAction, testRuleJsonAction } from "@/app/actions/dashboard";
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
}`;

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
  UNKNOWN: { label: "판정 불가", cls: "text-neutral-400" },
};

const FIELDS = [
  { key: "method", label: "메소드", width: "w-16" },
  { key: "path", label: "경로", width: "w-40" },
  { key: "query", label: "쿼리", width: "w-32" },
  { key: "userAgent", label: "User-Agent", width: "w-48" },
  { key: "ip", label: "IP", width: "w-28" },
] as const;

export function SandboxTab({ waf }: { waf: PollState<WafPanel> }) {
  const [ruleJson, setRuleJson] = useState("");
  const [requests, setRequests] = useState<TestRequest[] | null>(null);
  const [result, setResult] = useState<RuleTestResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void (async () => {
      const res = await getDefaultTestRequestsAction();
      if (res.ok) setRequests(res.data);
      else setError(res.error);
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

  const editField = (id: string, key: (typeof FIELDS)[number]["key"], value: string): void => {
    setRequests((prev) => (prev ?? []).map((r) => (r.id === id ? { ...r, [key]: value } : r)));
  };

  const addRow = (): void => {
    setRequests((prev) => [
      ...(prev ?? []),
      {
        id: `custom-${Date.now()}`,
        method: "GET",
        path: "/",
        query: "",
        userAgent: "Mozilla/5.0",
        ip: "10.0.2.1",
        country: "KR",
      },
    ]);
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
        AWS로 아무것도 전송하지 않고 WebACL도 건드리지 않습니다. 로컬에서 판정할 수 없는 문법은
        통과가 아니라 <span className="text-neutral-200">판정 불가</span>로 표시됩니다.
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
            <button
              type="button"
              onClick={addRow}
              className="rounded bg-neutral-800 px-2 py-0.5 text-[11px] text-neutral-300 hover:bg-neutral-700"
            >
              + 행 추가
            </button>
          }
        >
          {requests === null ? (
            <SectionLoading />
          ) : (
            <div className="max-h-80 overflow-auto">
              <table className="w-full text-left font-mono text-[10px]">
                <thead className="sticky top-0 bg-neutral-900 text-neutral-500">
                  <tr>
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
                    <tr key={r.id} className="border-t border-neutral-800">
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
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>

      {result && (
        <Card title={`결과 — ${result.ruleName} (Action: ${result.action})`}>
          <div
            className={`mb-2 rounded border px-3 py-2 text-[12px] font-semibold ${VERDICT_STYLE[result.verdict].cls}`}
          >
            {VERDICT_STYLE[result.verdict].label}
          </div>
          <div className="mb-2 flex gap-4 font-mono text-[11px]">
            <span className="text-emerald-400">통과 {result.passed}</span>
            <span className="text-red-400">차단 {result.blocked}</span>
            <span className="text-amber-400">카운트만 {result.counted}</span>
            <span className="text-neutral-400">판정 불가 {result.unknown}</span>
          </div>
          <table className="w-full text-left font-mono text-[10px]">
            <thead className="text-neutral-500">
              <tr>
                {["요청", "경로", "User-Agent", "결과", "이유"].map((h) => (
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
                    <td className="max-w-40 px-2 py-0.5">
                      <Truncate text={req?.path ?? ""} />
                    </td>
                    <td className="max-w-40 px-2 py-0.5 text-neutral-500">
                      <Truncate text={req?.userAgent ?? ""} />
                    </td>
                    <td className={`px-2 py-0.5 ${style?.cls ?? ""}`}>{style?.label ?? row.outcome}</td>
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
