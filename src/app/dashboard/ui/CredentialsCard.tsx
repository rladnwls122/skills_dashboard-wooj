"use client";

import { useEffect, useState } from "react";
import {
  checkCredentialsAction,
  clearCredentialsAction,
  getCredentialsAction,
  importAwsSessionAction,
  saveCredentialsAction,
} from "@/app/actions/dashboard";
import { parseCredentialBlob, credentialProblem } from "@/lib/awscreds";
import type { CredentialCheck, CredentialsView } from "@/lib/types";
import { Card, ErrorNote, SectionLoading } from "./shared";

// AWS 자격증명.
//
// Every panel on this dashboard fails at once when the keys are wrong or
// expired, and they all fail the same way — empty. So this card sits above the
// resource names: it says which key is in force, whether it still has time left
// on it, and it takes a new one without a restart.
//
// Two ways in, because both happen. `aws CLI 세션 불러오기` reads the session
// the operator already logged into (`aws sso login`, `aws configure`) — that is
// the one that refreshes itself when the token expires. Pasting is the fallback
// for a machine with no CLI, or keys handed over on paper.
//
// Nothing typed here comes back: the server returns a masked view only.

const SOURCE: Record<CredentialsView["source"], { text: string; cls: string }> = {
  screen: { text: "화면 주입", cls: "bg-sky-950/70 text-sky-300 border-sky-800" },
  env: { text: ".env", cls: "bg-neutral-800 text-neutral-300 border-neutral-700" },
  chain: { text: "기본 체인", cls: "bg-neutral-900 text-neutral-500 border-neutral-800" },
};

const CHECK: Record<CredentialCheck["status"], { text: string; cls: string }> = {
  OK: { text: "확인됨", cls: "border-emerald-800 bg-emerald-950/40 text-emerald-300" },
  // Authenticated but the probe call is denied — still a working key.
  DENIED: { text: "유효 (권한 제한)", cls: "border-amber-800 bg-amber-950/40 text-amber-200" },
  AUTH_FAIL: { text: "인증 실패", cls: "border-red-900 bg-red-950/40 text-red-300" },
  NO_CREDENTIALS: { text: "자격증명 없음", cls: "border-red-900 bg-red-950/40 text-red-300" },
};

function fmtLeft(ms: number): string {
  if (ms <= 0) return "만료됨";
  const min = Math.floor(ms / 60_000);
  if (min < 60) return `${min}분 남음`;
  return `${Math.floor(min / 60)}시간 ${min % 60}분 남음`;
}

export function CredentialsCard() {
  const [view, setView] = useState<CredentialsView | null>(null);
  const [check, setCheck] = useState<CredentialCheck | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [blob, setBlob] = useState("");
  const [keyId, setKeyId] = useState("");
  const [secret, setSecret] = useState("");
  const [token, setToken] = useState("");
  const [profile, setProfile] = useState("");
  const [persist, setPersist] = useState(false);

  const load = async (): Promise<void> => {
    const res = await getCredentialsAction();
    if (res.ok) {
      setView(res.data);
      setError(null);
      if (profile === "") setProfile(res.data.profile || res.data.defaultProfile);
      setPersist(res.data.persisted);
    } else {
      setError(res.error);
    }
  };

  useEffect(() => {
    void load();
    // The countdown is the point of the expiry line, so it is re-read on a
    // slow timer rather than only on mount.
    const id = setInterval(() => void load(), 30_000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const clearInputs = (): void => {
    setBlob("");
    setKeyId("");
    setSecret("");
    setToken("");
  };

  const apply = (label: string, run: () => Promise<void>) => async (): Promise<void> => {
    setBusy(label);
    setError(null);
    await run();
    setBusy(null);
  };

  const importSession = apply("import", async () => {
    const res = await importAwsSessionAction({ profile, persist });
    if (res.ok) {
      setView(res.data.view);
      setCheck(res.data.check);
      clearInputs();
    } else {
      setError(res.error);
    }
  });

  // The paste box wins over the three fields when it holds a complete set —
  // pasting into it and then pressing save is the common motion, and asking
  // someone to press "채우기" first is a step that only exists to be forgotten.
  const pasted = blob.trim() === "" ? null : parseCredentialBlob(blob);
  const effective = {
    accessKeyId: keyId.trim() || pasted?.accessKeyId || "",
    secretAccessKey: secret.trim() || pasted?.secretAccessKey || "",
    sessionToken: token.trim() || pasted?.sessionToken || "",
    expiration: pasted?.expiration ?? "",
  };
  const problem = credentialProblem(effective);

  const save = apply("save", async () => {
    const res = await saveCredentialsAction({
      accessKeyId: keyId.trim(),
      secretAccessKey: secret.trim(),
      sessionToken: token.trim(),
      blob,
      persist,
    });
    if (res.ok) {
      setView(res.data.view);
      setCheck(res.data.check);
      clearInputs();
    } else {
      setError(res.error);
    }
  });

  const verify = apply("check", async () => {
    const res = await checkCredentialsAction();
    if (res.ok) {
      setView(res.data.view);
      setCheck(res.data.check);
    } else {
      setError(res.error);
    }
  });

  const clear = apply("clear", async () => {
    const res = await clearCredentialsAction();
    if (res.ok) {
      setView(res.data.view);
      setCheck(res.data.check);
      clearInputs();
    } else {
      setError(res.error);
    }
  });

  const src = view ? SOURCE[view.source] : null;
  const expiring = view?.expiresInMs !== null && view?.expiresInMs !== undefined;

  return (
    <Card
      title="AWS 자격증명"
      limit="화면 주입 > .env > 기본 체인"
      right={
        <div className="flex items-center gap-2">
          <ErrorNote error={error} />
          <button
            type="button"
            disabled={busy !== null}
            onClick={() => void verify()}
            className="rounded bg-neutral-800 px-2 py-1 font-mono text-[10px] text-neutral-300 hover:bg-neutral-700 disabled:opacity-40"
          >
            {busy === "check" ? "확인 중…" : "연결 확인"}
          </button>
        </div>
      }
    >
      {!view ? (
        <SectionLoading />
      ) : (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
            <span className={`rounded-[3px] border px-1 font-mono text-[9px] ${src!.cls}`}>
              {src!.text}
            </span>
            <span className="font-mono text-[11px] text-neutral-200">
              {view.accessKeyIdMasked || "(없음)"}
            </span>
            {view.temporary && (
              <span className="rounded-[3px] border border-neutral-700 bg-neutral-800 px-1 font-mono text-[9px] text-neutral-300">
                임시 키
              </span>
            )}
            {view.hasSessionToken && (
              <span className="font-mono text-[10px] text-neutral-500">+ session token</span>
            )}
            {view.source === "screen" && (
              <span className="font-mono text-[10px] text-neutral-500">
                {view.origin === "cli" ? `aws CLI · ${view.profile}` : "직접 입력"} ·{" "}
                {view.persisted ? "SQLite 저장됨" : "이 세션에만"}
              </span>
            )}
            {expiring && (
              <span
                className={`font-mono text-[10px] ${
                  (view.expiresInMs ?? 0) <= 5 * 60_000 ? "text-amber-400" : "text-neutral-500"
                }`}
              >
                {fmtLeft(view.expiresInMs ?? 0)}
              </span>
            )}
          </div>

          {check && (
            <div className={`rounded border px-2 py-1 font-mono text-[10px] ${CHECK[check.status].cls}`}>
              {CHECK[check.status].text} · {check.detail}
            </div>
          )}

          <div className="flex flex-wrap items-center gap-2">
            <input
              value={profile}
              onChange={(e) => setProfile(e.target.value)}
              placeholder="default"
              spellCheck={false}
              title="aws CLI 프로파일"
              className="w-28 rounded border border-neutral-800 bg-neutral-900 px-2 py-1 font-mono text-[11px] text-neutral-200"
            />
            <button
              type="button"
              disabled={busy !== null}
              onClick={() => void importSession()}
              className="rounded bg-sky-900 px-2 py-1 font-mono text-[10px] font-semibold text-sky-100 hover:bg-sky-800 disabled:opacity-40"
            >
              {busy === "import" ? "불러오는 중…" : "aws CLI 세션 불러오기"}
            </button>
            {view.source === "screen" && (
              <button
                type="button"
                disabled={busy !== null}
                onClick={() => void clear()}
                title=".env / 기본 체인으로 되돌립니다"
                className="rounded bg-neutral-800 px-2 py-1 font-mono text-[10px] text-neutral-300 hover:bg-neutral-700 disabled:opacity-40"
              >
                주입 해제
              </button>
            )}
            <button
              type="button"
              onClick={() => setOpen((v) => !v)}
              className="rounded bg-neutral-800 px-2 py-1 font-mono text-[10px] text-neutral-300 hover:bg-neutral-700"
            >
              {open ? "직접 입력 닫기" : "키 직접 입력"}
            </button>
          </div>

          <div className="text-[10px] leading-4 text-neutral-500">
            <span className="text-neutral-300">aws CLI 세션 불러오기</span>는 로컬에 로그인된
            세션(`aws sso login` / `aws configure`)의 임시 키와 session token 을 그대로 가져오고,
            만료가 가까워지면 자동으로 다시 읽습니다. 쿠버네티스 접근은 kubeconfig 를 쓰므로 이
            설정의 영향을 받지 않습니다.
          </div>

          {open && (
            <div className="space-y-2 rounded border border-neutral-800 bg-neutral-950 p-2">
              <textarea
                value={blob}
                onChange={(e) => setBlob(e.target.value)}
                rows={4}
                spellCheck={false}
                placeholder={
                  "여기에 통째로 붙여넣기 — export AWS_ACCESS_KEY_ID=… / .env / [profile] / CLI JSON 모두 인식"
                }
                className="w-full rounded border border-neutral-800 bg-neutral-900 px-2 py-1 font-mono text-[10px] text-neutral-200"
              />
              <div className="grid gap-1.5 sm:grid-cols-3">
                <input
                  value={keyId}
                  onChange={(e) => setKeyId(e.target.value)}
                  placeholder={pasted?.accessKeyId || "AWS_ACCESS_KEY_ID"}
                  spellCheck={false}
                  className="rounded border border-neutral-800 bg-neutral-900 px-2 py-1 font-mono text-[11px] text-neutral-200"
                />
                <input
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  type="password"
                  placeholder={pasted?.secretAccessKey ? "(붙여넣기에서 인식됨)" : "AWS_SECRET_ACCESS_KEY"}
                  spellCheck={false}
                  className="rounded border border-neutral-800 bg-neutral-900 px-2 py-1 font-mono text-[11px] text-neutral-200"
                />
                <input
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  type="password"
                  placeholder={pasted?.sessionToken ? "(붙여넣기에서 인식됨)" : "AWS_SESSION_TOKEN (임시 키만)"}
                  spellCheck={false}
                  className="rounded border border-neutral-800 bg-neutral-900 px-2 py-1 font-mono text-[11px] text-neutral-200"
                />
              </div>
              <div className="flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  disabled={busy !== null || problem !== null}
                  onClick={() => void save()}
                  className="rounded bg-sky-900 px-3 py-1 font-mono text-[11px] font-semibold text-sky-100 hover:bg-sky-800 disabled:opacity-40"
                >
                  {busy === "save" ? "적용 중…" : "적용"}
                </button>
                {problem && <span className="font-mono text-[10px] text-amber-400">{problem}</span>}
              </div>
            </div>
          )}

          <label className="flex items-center gap-1.5 text-[10px] text-neutral-500">
            <input
              type="checkbox"
              checked={persist}
              onChange={(e) => setPersist(e.target.checked)}
              className="accent-sky-600"
            />
            {/* Off by default: persisting writes the secret to data/dashboard.db
                in plain text. Worth having — a dev-server restart otherwise
                costs another paste — but it is the operator's call. */}
            재시작 후에도 유지 (SQLite 에 평문 저장 · 기본은 이 세션에만)
          </label>
        </div>
      )}
    </Card>
  );
}
