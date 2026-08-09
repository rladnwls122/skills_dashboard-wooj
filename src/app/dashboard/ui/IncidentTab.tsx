"use client";

import { useState } from "react";
import { generateIncidentContextAction } from "@/app/actions/dashboard";
import type { IncidentContextResult } from "@/lib/types";
import { Card } from "./shared";

export function IncidentTab() {
  const [result, setResult] = useState<IncidentContextResult | null>(null);
  const [format, setFormat] = useState<"markdown" | "json">("markdown");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const generate = async (): Promise<void> => {
    setBusy(true);
    setError(null);
    const res = await generateIncidentContextAction();
    if (res.ok) setResult(res.data);
    else setError(res.error);
    setBusy(false);
  };

  const content = result ? (format === "markdown" ? result.markdown : result.json) : "";

  const copy = async (): Promise<void> => {
    if (!content) return;
    await navigator.clipboard.writeText(content);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const download = (): void => {
    if (!result) return;
    const blob = new Blob([content], {
      type: format === "markdown" ? "text/markdown" : "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `incident-context-${result.generatedAt.replaceAll(":", "-")}.${format === "markdown" ? "md" : "json"}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="space-y-3">
      <Card
        title="Incident Context (Amazon Q용)"
        right={
          <div className="flex items-center gap-2 text-xs">
            <button
              type="button"
              disabled={busy}
              onClick={() => void generate()}
              className="rounded bg-sky-900/70 px-3 py-1 font-semibold text-sky-100 hover:bg-sky-900 disabled:opacity-50"
            >
              {busy ? "생성 중…" : "Generate Incident Context"}
            </button>
            {result && (
              <>
                <select
                  value={format}
                  onChange={(e) => setFormat(e.target.value as "markdown" | "json")}
                  className="rounded border border-neutral-700 bg-neutral-900 px-2 py-1"
                >
                  <option value="markdown">Markdown</option>
                  <option value="json">JSON</option>
                </select>
                <button
                  type="button"
                  onClick={() => void copy()}
                  className="rounded bg-neutral-800 px-2 py-1 text-neutral-300 hover:bg-neutral-700"
                >
                  {copied ? "복사됨!" : "복사"}
                </button>
                <button
                  type="button"
                  onClick={download}
                  className="rounded bg-neutral-800 px-2 py-1 text-neutral-300 hover:bg-neutral-700"
                >
                  다운로드
                </button>
              </>
            )}
          </div>
        }
      >
        <p className="mb-2 text-[11px] text-neutral-500">
          현재 시점의 메트릭·WAF·K8s·로그·타임라인·조치 이력을 하나의 스냅샷으로 묶어 Amazon Q 또는
          운영자가 바로 분석 가능한 형식으로 생성. 민감정보(토큰/비밀번호/쿠키/AWS 키)는 서버에서
          마스킹 후 반환. 자동 차단/정책 변경 없음 — 분석 컨텍스트 생성 전용.
        </p>
        {error && (
          <div className="mb-2 rounded border border-red-900 bg-red-950/40 px-2 py-1 text-xs text-red-300">
            {error}
          </div>
        )}
        {result ? (
          <pre className="max-h-[560px] overflow-auto rounded bg-black p-3 font-mono text-[11px] leading-4 whitespace-pre-wrap text-neutral-300">
            {content}
          </pre>
        ) : (
          <div className="py-8 text-center text-xs text-neutral-600">
            버튼을 눌러 Incident Snapshot + Context 생성
          </div>
        )}
      </Card>
    </div>
  );
}
