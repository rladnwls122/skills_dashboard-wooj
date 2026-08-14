import "server-only";

// Which AWS credentials every client in this process signs with, and how to
// change them without restarting.
//
// .env is read once at boot, so a key that arrives after the server started —
// or a session token that expires during the exercise — used to mean editing a
// file and restarting, losing the sampled history in the process. Here the keys
// can be injected from the 설정 screen instead: pasted, or read straight out of
// the local `aws` CLI session (see awslogin.ts).
//
// Precedence: 화면 주입 > .env / 환경변수 > SDK 기본 체인(~/.aws, IRSA, 인스턴스
// 역할). Nothing is injected by default, so an environment that already works
// through the default chain keeps working exactly as before.
//
// Storage: the injected keys live either in this process's memory (기본값 —
// gone on restart) or, if the operator asks for it, in the same local SQLite
// the other settings use. Persisting writes a secret to disk in plain text;
// that is the operator's call to make, so it is a switch on the screen and not
// a default.

import { loadSettings, saveSetting } from "./db";
import { readCliSession, activeProfile } from "./awslogin";
import {
  credentialProblem,
  expiresInMs,
  isComplete,
  maskKeyId,
  maskSecret,
  type ParsedCredentials,
} from "@/lib/awscreds";
import type { CredentialOrigin, CredentialsView } from "@/lib/types";

// Rows in the settings table. Prefixed like the environment variables they
// shadow so a `SELECT * FROM settings` during troubleshooting reads plainly.
const K_ID = "AWS_ACCESS_KEY_ID";
const K_SECRET = "AWS_SECRET_ACCESS_KEY";
const K_TOKEN = "AWS_SESSION_TOKEN";
const K_EXPIRES = "AWS_CREDENTIAL_EXPIRATION";
const K_ORIGIN = "AWS_CREDENTIAL_ORIGIN";
const K_PROFILE = "AWS_CREDENTIAL_PROFILE";

export interface InjectedCredentials extends ParsedCredentials {
  origin: CredentialOrigin;
  // The CLI profile an "aws CLI 세션 불러오기" import came from. Kept so the
  // refresh below can re-read the same profile rather than guessing.
  profile: string;
  persisted: boolean;
}

// Session-only store. A module variable rather than a cache entry: it must not
// expire on its own, and it must not be reachable from the panel cache that
// `invalidateCached("")` empties on every settings save.
let memory: InjectedCredentials | null = null;

function fromDb(): InjectedCredentials | null {
  let rows: Record<string, string>;
  try {
    rows = loadSettings();
  } catch {
    // A locked or missing database must not take AWS access down with it.
    return null;
  }
  const id = rows[K_ID] ?? "";
  const secret = rows[K_SECRET] ?? "";
  if (id === "" || secret === "") return null;
  return {
    accessKeyId: id,
    secretAccessKey: secret,
    sessionToken: rows[K_TOKEN] ?? "",
    expiration: rows[K_EXPIRES] ?? "",
    origin: (rows[K_ORIGIN] as CredentialOrigin) ?? "paste",
    profile: rows[K_PROFILE] ?? "",
    persisted: true,
  };
}

// What the screen injected, memory first: a session-only injection is the more
// recent decision, and it is the one an operator makes when they specifically
// do not want the key on disk.
export function injected(): InjectedCredentials | null {
  return memory ?? fromDb();
}

function envCredentials(): ParsedCredentials {
  return {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID ?? "",
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ?? "",
    sessionToken: process.env.AWS_SESSION_TOKEN ?? "",
    expiration: "",
  };
}

export interface SaveCredentialsInput extends Partial<ParsedCredentials> {
  origin: CredentialOrigin;
  profile?: string;
  persist: boolean;
}

// Replaces whatever is injected. Callers must reset the SDK clients afterwards
// — they capture the credential provider at construction.
export function setCredentials(input: SaveCredentialsInput): InjectedCredentials {
  const next: ParsedCredentials = {
    accessKeyId: (input.accessKeyId ?? "").trim(),
    secretAccessKey: (input.secretAccessKey ?? "").trim(),
    sessionToken: (input.sessionToken ?? "").trim(),
    expiration: (input.expiration ?? "").trim(),
  };
  const problem = credentialProblem(next);
  if (problem) throw new Error(problem);

  const record: InjectedCredentials = {
    ...next,
    origin: input.origin,
    profile: (input.profile ?? "").trim(),
    persisted: input.persist,
  };

  if (input.persist) {
    memory = null;
    saveSetting(K_ID, record.accessKeyId);
    saveSetting(K_SECRET, record.secretAccessKey);
    saveSetting(K_TOKEN, record.sessionToken);
    saveSetting(K_EXPIRES, record.expiration);
    saveSetting(K_ORIGIN, record.origin);
    saveSetting(K_PROFILE, record.profile);
  } else {
    // Switching to session-only has to remove the disk copy too, or the next
    // restart silently resurrects a key the operator meant to stop using.
    clearStored();
    memory = record;
  }
  return record;
}

function clearStored(): void {
  try {
    for (const k of [K_ID, K_SECRET, K_TOKEN, K_EXPIRES, K_ORIGIN, K_PROFILE]) {
      // "" is this table's delete signal (see db.saveSetting).
      saveSetting(k, "");
    }
  } catch {
    // Nothing stored, or no database — clearing memory below is what matters.
  }
}

// Stops injecting. The process falls back to .env / the SDK default chain,
// which is also what a fresh checkout does.
export function clearCredentials(): void {
  memory = null;
  clearStored();
}

// A CLI-imported session is refreshed this long before it expires. The SDK
// refreshes on its own schedule too; this is the margin used when the provider
// is asked for credentials directly.
const REFRESH_MARGIN_MS = 5 * 60_000;

let refreshing: Promise<InjectedCredentials> | null = null;

// Re-reads the CLI session behind an existing import. One flight at a time:
// every panel polls, and an expired token would otherwise start a CLI process
// per in-flight request.
async function refreshFromCli(current: InjectedCredentials): Promise<InjectedCredentials> {
  if (refreshing) return refreshing;
  refreshing = (async () => {
    try {
      const session = await readCliSession(current.profile || undefined);
      return setCredentials({
        ...session,
        origin: "cli",
        profile: session.profile,
        persist: current.persisted,
      });
    } finally {
      refreshing = null;
    }
  })();
  return refreshing;
}

export interface ResolvedCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken?: string;
  expiration?: Date;
}

// The credential provider handed to every SDK client, or undefined to leave the
// SDK's own chain in charge.
//
// A provider function rather than a fixed object: temporary keys expire, and
// the SDK re-invokes the provider once `expiration` passes. That is what makes
// an `aws sso login` session keep working after the dashboard has been running
// for hours — the token is re-read from the CLI instead of the whole process
// failing with InvalidClientTokenId.
export function awsCredentialProvider(): (() => Promise<ResolvedCredentials>) | undefined {
  if (!injected()) return undefined;
  return async () => {
    let current = injected();
    if (!current) throw new Error("주입된 AWS 자격증명이 없습니다.");

    const left = expiresInMs(current.expiration, Date.now());
    if (left !== null && left < REFRESH_MARGIN_MS) {
      if (current.origin === "cli") {
        current = await refreshFromCli(current);
      } else if (left <= 0) {
        throw new Error(
          "주입된 임시 자격증명이 만료되었습니다 — 설정 탭에서 세션을 다시 불러오거나 키를 다시 붙여넣으세요.",
        );
      }
    }

    const out: ResolvedCredentials = {
      accessKeyId: current.accessKeyId,
      secretAccessKey: current.secretAccessKey,
    };
    if (current.sessionToken !== "") out.sessionToken = current.sessionToken;
    const exp = current.expiration === "" ? NaN : Date.parse(current.expiration);
    if (Number.isFinite(exp)) out.expiration = new Date(exp);
    return out;
  };
}

// Forces a re-read of the CLI session for the profile given (or the one the
// current import used). Returns what is now in force.
export async function importCliSession(
  profile: string | undefined,
  persist: boolean,
): Promise<InjectedCredentials> {
  const session = await readCliSession(profile);
  return setCredentials({
    ...session,
    origin: "cli",
    profile: session.profile,
    persist,
  });
}

// What the 설정 screen draws. Masked throughout — the secret and the session
// token never leave the server, in either direction.
export function credentialsView(nowMs: number): CredentialsView {
  const inj = injected();
  const env = envCredentials();
  const source = inj ? "screen" : isComplete(env) ? "env" : "chain";
  const shown = inj ?? env;
  const left = inj ? expiresInMs(inj.expiration, nowMs) : null;
  return {
    source,
    origin: inj?.origin ?? null,
    persisted: inj?.persisted ?? false,
    profile: inj?.profile ?? "",
    accessKeyIdMasked: maskKeyId(shown.accessKeyId),
    secretMasked: maskSecret(shown.secretAccessKey),
    hasSessionToken: shown.sessionToken !== "",
    temporary: /^ASIA/i.test(shown.accessKeyId),
    expiration: inj?.expiration ?? "",
    expiresInMs: left,
    envAccessKeyIdMasked: maskKeyId(env.accessKeyId),
    defaultProfile: activeProfile(),
  };
}
