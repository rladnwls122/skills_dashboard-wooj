"use client";

import { useEffect, useState } from "react";
import { discoverAction, getSettingsAction, saveSettingsAction } from "@/app/actions/dashboard";
import type { DiscoverKind, DiscoveryResult, SettingRow, SettingsView } from "@/lib/types";
import { Card, CopyValue, ErrorNote, SectionLoading } from "./shared";

// 설정.
//
// .env is read once at process start, so every wrong resource name used to cost
// a file edit and a restart. Here the same values can be corrected on screen,
// and — more usefully — filled from what the account actually has, because the
// failure mode of a mistyped name is not an error but an empty panel.
//
// Each row says where its value came from. "skills-waf" with no provenance
// cannot be debugged when it turns out to be a built-in default pointing at
// nothing.

const SOURCE_LABEL: Record<SettingRow["source"], { text: string; cls: string }> = {
  screen: { text: "화면 설정", cls: "bg-sky-950/70 text-sky-300 border-sky-800" },
  env: { text: ".env", cls: "bg-neutral-800 text-neutral-300 border-neutral-700" },
  default: { text: "기본값", cls: "bg-neutral-900 text-neutral-500 border-neutral-800" },
};

export function SettingsTab() {
  const [view, setView] = useState<SettingsView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [found, setFound] = useState<Record<string, DiscoveryResult>>({});
  const [message, setMessage] = useState<string | null>(null);

  const load = async (): Promise<void> => {
    const res = await getSettingsAction();
    if (res.ok) {
      setView(res.data);
      setError(null);
    } else {
      setError(res.error);
    }
  };

  useEffect(() => {
    void load();
  }, []);

  const runDiscover = async (key: string, kind: DiscoverKind): Promise<void> => {
    setBusy(key);
    setMessage(null);
    const res = await discoverAction(kind);
    if (res.ok) {
      setFound((prev) => ({ ...prev, [key]: res.data }));
      // One candidate and nothing to choose between: fill it in rather than
      // making the operator click the only option.
      if (res.data.resources.length === 1) {
        setDraft((prev) => ({ ...prev, [key]: res.data.resources[0]!.id }));
      }
    } else {
      setMessage(`탐색 실패: ${res.error}`);
    }
    setBusy(null);
  };

  const save = async (): Promise<void> => {
    setBusy("save");
    setMessage(null);
    const res = await saveSettingsAction(draft);
    if (res.ok) {
      setView(res.data);
      setDraft({});
      setFound({});
      setMessage("저장됨 — 캐시를 비우고 AWS 클라이언트를 새로 만들었습니다. 재시작 없이 다음 조회부터 적용됩니다.");
    } else {
      setMessage(`저장 실패: ${res.error}`);
    }
    setBusy(null);
  };

  const clearOne = (key: string): void => {
    // An empty string is the signal to stop overriding, so this queues a
    // deletion rather than writing "" as a value.
    setDraft((prev) => ({ ...prev, [key]: "" }));
  };

  const dirty = Object.keys(draft).length > 0;

  return (
    <div className="space-y-3">
      <div className="rounded border border-neutral-800 bg-neutral-900/70 px-3 py-2 text-[11px] leading-5 text-neutral-400">
        이 화면에서 바꾼 값은 <span className="text-neutral-200">.env 보다 우선</span>하며 SQLite 에
        저장되어 <span className="text-neutral-200">재시작 없이</span> 적용됩니다. 이름을 직접
        입력하는 대신 <span className="text-neutral-200">자동 탐색</span>으로 계정에 실제로 있는
        리소스를 골라 넣을 수 있습니다 — 이름을 잘못 적으면 오류가 아니라 &ldquo;빈 패널&rdquo;로
        나타나기 때문에, 고르는 편이 안전합니다. 값을 비우면 그 항목은 다시 .env(또는 기본값)를
        따릅니다.
      </div>

      <ErrorNote error={error} />
      {message && (
        <div className="rounded border border-sky-900 bg-sky-950/40 px-3 py-2 text-[11px] text-sky-200">
          {message}
        </div>
      )}

      <Card title="환경 설정" limit="화면 설정 > .env > 기본값 순">
        {!view ? (
          <SectionLoading />
        ) : (
          <div className="space-y-2">
            {view.rows.map((row) => {
              const pending = draft[row.key];
              const shown = pending !== undefined ? pending : row.value;
              const src = SOURCE_LABEL[row.source];
              const list = found[row.key];
              return (
                <div key={row.key} className="rounded border border-neutral-800 bg-neutral-950 p-2">
                  <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                    <span className="font-mono text-[11px] font-semibold text-neutral-200">
                      {row.label}
                    </span>
                    <span className="font-mono text-[10px] text-neutral-600">{row.key}</span>
                    <span
                      className={`rounded-[3px] border px-1 font-mono text-[9px] ${src.cls}`}
                      title={
                        row.source === "screen"
                          ? `.env 값(${row.envValue || "없음"})을 덮어쓰는 중`
                          : row.source === "env"
                            ? ".env 에서 읽음"
                            : "코드에 내장된 기본값"
                      }
                    >
                      {src.text}
                    </span>
                    {pending !== undefined && (
                      <span className="rounded-[3px] bg-amber-950/60 px-1 font-mono text-[9px] text-amber-300">
                        저장 안 됨
                      </span>
                    )}
                  </div>

                  <div className="mt-1 flex flex-wrap items-center gap-2">
                    <input
                      value={shown}
                      onChange={(e) => setDraft((prev) => ({ ...prev, [row.key]: e.target.value }))}
                      placeholder={row.defaultValue || "(비어 있음)"}
                      spellCheck={false}
                      className="min-w-0 flex-1 rounded border border-neutral-800 bg-neutral-900 px-2 py-1 font-mono text-[11px] text-neutral-200"
                    />
                    {row.discover && (
                      <button
                        type="button"
                        disabled={busy !== null}
                        onClick={() => void runDiscover(row.key, row.discover!)}
                        className="shrink-0 rounded bg-sky-900 px-2 py-1 font-mono text-[10px] font-semibold text-sky-100 hover:bg-sky-800 disabled:opacity-40"
                      >
                        {busy === row.key ? "탐색 중…" : "자동 탐색"}
                      </button>
                    )}
                    {row.source === "screen" && (
                      <button
                        type="button"
                        onClick={() => clearOne(row.key)}
                        title=".env / 기본값으로 되돌립니다"
                        className="shrink-0 rounded bg-neutral-800 px-2 py-1 font-mono text-[10px] text-neutral-300 hover:bg-neutral-700"
                      >
                        해제
                      </button>
                    )}
                  </div>

                  <div className="mt-1 text-[10px] leading-4 text-neutral-500">{row.hint}</div>

                  {list && (
                    <div className="mt-1.5 rounded border border-neutral-800 bg-neutral-900 p-1.5">
                      {list.resources.length > 0 && (
                        <div className="space-y-0.5">
                          {list.resources.map((r) => (
                            <button
                              key={r.id}
                              type="button"
                              onClick={() => setDraft((prev) => ({ ...prev, [row.key]: r.id }))}
                              className={`flex w-full items-baseline justify-between gap-2 rounded px-1.5 py-0.5 text-left text-[10px] hover:bg-neutral-800 ${
                                shown === r.id ? "bg-sky-950/50 text-sky-200" : "text-neutral-300"
                              }`}
                            >
                              <span className="font-mono break-all">{r.id}</span>
                              <span className="shrink-0 text-neutral-500">
                                {r.current ? "현재 사용 중 · " : ""}
                                {r.detail}
                              </span>
                            </button>
                          ))}
                        </div>
                      )}
                      {/* Why a listing came back short, when it did. A denied
                          call that is silently dropped reads as "the account
                          has none of these". */}
                      {list.notes.map((n) => (
                        <div key={n} className="mt-0.5 text-[10px] leading-4 text-amber-400/90">
                          · {n}
                        </div>
                      ))}
                      {list.resources.length === 0 && list.notes.length === 0 && (
                        <div className="text-[10px] text-neutral-600">후보 없음</div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}

            <div className="flex items-center gap-2 pt-1">
              <button
                type="button"
                disabled={!dirty || busy !== null}
                onClick={() => void save()}
                className="rounded bg-sky-900 px-3 py-1.5 font-mono text-[11px] font-semibold text-sky-100 hover:bg-sky-800 disabled:opacity-40"
              >
                {busy === "save" ? "저장 중…" : "저장"}
              </button>
              <button
                type="button"
                disabled={!dirty}
                onClick={() => setDraft({})}
                className="rounded bg-neutral-800 px-3 py-1.5 font-mono text-[11px] text-neutral-300 hover:bg-neutral-700 disabled:opacity-40"
              >
                되돌리기
              </button>
              {dirty && (
                <span className="font-mono text-[10px] text-amber-400">
                  {Object.keys(draft).length}개 항목이 저장되지 않았습니다
                </span>
              )}
            </div>
          </div>
        )}
      </Card>

      {view && view.envText && (
        <Card
          title=".env 로 고정하기"
        >
          <div className="space-y-1">
            <pre className="rounded bg-black p-2 font-mono text-[10px] leading-4 whitespace-pre-wrap text-emerald-300">
              {view.envText}
            </pre>
            <CopyValue value=".env 에 붙여넣을 내용 복사" copy={view.envText} className="text-[11px] text-neutral-300" />
          </div>
        </Card>
      )}
    </div>
  );
}
