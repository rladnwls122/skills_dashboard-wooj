// Which AWS credentials every client in this process signs with, and how to
// change them without restarting.
//
// The environment is read once at boot, so a key that arrives after the server
// started — or a session token that expires during the exercise — would
// otherwise mean editing a file and restarting, losing the sampled history in
// the process. Here the keys can be injected from the 설정 screen instead:
// pasted, or resolved from a local `aws` profile (SSO included) through the
// SDK's own shared-config chain.
//
// Precedence: 화면 주입 > 환경변수 > SDK 기본 체인(~/.aws, IRSA, 인스턴스 역할).
// Nothing is injected by default, so an environment that already works through
// the default chain keeps working exactly as before.
//
// Storage: the injected keys live either in this process's memory (기본값 —
// gone on restart) or, if the operator asks for it, in the same local SQLite
// the other settings use. Persisting writes a secret to disk in plain text;
// that is the operator's call to make, so it is a switch on the screen and not
// a default.

import { fromIni } from "@aws-sdk/credential-providers";
import type { AwsCredentialIdentity, AwsCredentialIdentityProvider } from "@aws-sdk/types";

import {
  credentialProblem,
  expiresInMs,
  isComplete,
  maskKeyId,
  maskSecret,
  type ParsedCredentials,
} from "../../src/lib/awscreds.ts";
import type { CredentialOrigin, CredentialsView } from "../../src/lib/types.ts";
import type { Store } from "../store/store.ts";

// Rows in the settings table. Prefixed like the environment variables they
// shadow so a `SELECT * FROM settings` during troubleshooting reads plainly.
const K_ID = "AWS_ACCESS_KEY_ID";
const K_SECRET = "AWS_SECRET_ACCESS_KEY";
const K_TOKEN = "AWS_SESSION_TOKEN";
const K_EXPIRES = "AWS_CREDENTIAL_EXPIRATION";
const K_ORIGIN = "AWS_CREDENTIAL_ORIGIN";
const K_PROFILE = "AWS_CREDENTIAL_PROFILE";

/**
 * What a settings save must leave alone: these rows are written by this file,
 * not by the settings screen.
 */
export const STORED_KEYS = [K_ID, K_SECRET, K_TOKEN, K_EXPIRES, K_ORIGIN, K_PROFILE];

// A profile name reaches the shared-config loader as a lookup key. Everything
// outside the shape AWS itself allows is refused rather than escaped — the
// value comes from a text box on a page with no login.
const PROFILE_SHAPE = /^[A-Za-z0-9_.@=+-]{1,128}$/;

/** A credential set the screen put in force. */
export interface Injected extends ParsedCredentials {
  origin: CredentialOrigin;
  /**
   * The profile a "cli" import came from. Kept so the refresh below can re-read
   * the same profile rather than guessing.
   */
  profile: string;
  persisted: boolean;
}

/**
 * A CLI-imported session is refreshed this long before it expires. The SDK
 * refreshes on its own schedule too; this is the margin used when the provider
 * is asked for credentials directly.
 */
const REFRESH_MARGIN_MS = 5 * 60_000;

export interface SetInput extends ParsedCredentials {
  origin?: string;
  profile?: string;
  persist?: boolean;
}

export function isTemporary(c: ParsedCredentials): boolean {
  return /^ASIA/i.test(c.accessKeyId);
}

/** Accepts the ISO-8601 shapes the CLI and the console produce. */
export function parseExpiration(expiration: string): Date | null {
  const s = expiration.trim();
  if (s === "") return null;
  const t = Date.parse(s);
  return Number.isFinite(t) ? new Date(t) : null;
}

/** The profile the SDK would resolve on its own. */
export function defaultProfile(): string {
  const p = (process.env.AWS_PROFILE ?? "").trim();
  return p !== "" ? p : "default";
}

function envCredentials(): ParsedCredentials {
  return {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID ?? "",
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY ?? "",
    sessionToken: process.env.AWS_SESSION_TOKEN ?? "",
    expiration: "",
  };
}

export class Manager {
  private readonly store: Store | null;
  /** Injected for the clock, so tests do not have to wait out a margin. */
  now: () => number = () => Date.now();

  /**
   * Session-only store. Held here rather than in the panel cache: it must not
   * expire on its own, and it must not be reachable from the invalidation a
   * settings save performs.
   */
  private memory: Injected | null = null;

  /**
   * One CLI re-read at a time. Every panel polls, and an expired token would
   * otherwise start a profile resolution per in-flight request.
   */
  private refreshing: Promise<Injected> | null = null;

  constructor(store: Store | null) {
    this.store = store;
  }

  private fromDb(): Injected | null {
    if (!this.store) return null;
    let rows: Record<string, string>;
    try {
      rows = this.store.loadSettings();
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
      origin: rows[K_ORIGIN] === "cli" ? "cli" : "paste",
      profile: rows[K_PROFILE] ?? "",
      persisted: true,
    };
  }

  /**
   * What the screen put in force, memory first: a session-only injection is the
   * more recent decision, and it is the one an operator makes when they
   * specifically do not want the key on disk.
   */
  injected(): Injected | null {
    return this.memory ?? this.fromDb();
  }

  /**
   * Replaces whatever is injected. Callers must reset the SDK clients afterwards
   * — they capture the credential provider at construction.
   */
  set(input: SetInput): Injected {
    const next: ParsedCredentials = {
      accessKeyId: input.accessKeyId.trim(),
      secretAccessKey: input.secretAccessKey.trim(),
      sessionToken: (input.sessionToken ?? "").trim(),
      expiration: (input.expiration ?? "").trim(),
    };
    const problem = credentialProblem(next);
    if (problem) throw new Error(problem);

    const record: Injected = {
      ...next,
      origin: input.origin === "cli" ? "cli" : "paste",
      profile: (input.profile ?? "").trim(),
      persisted: input.persist === true,
    };

    if (record.persisted) {
      this.memory = null;
      const now = this.now();
      const pairs: [string, string][] = [
        [K_ID, record.accessKeyId],
        [K_SECRET, record.secretAccessKey],
        [K_TOKEN, record.sessionToken],
        [K_EXPIRES, record.expiration],
        [K_ORIGIN, record.origin],
        [K_PROFILE, record.profile],
      ];
      for (const [k, v] of pairs) {
        try {
          this.store?.saveSetting(k, v, now);
        } catch (e) {
          throw new Error(`자격증명 저장 실패: ${(e as Error).message}`);
        }
      }
      return record;
    }

    // Switching to session-only has to remove the disk copy too, or the next
    // restart silently resurrects a key the operator meant to stop using.
    this.clearStored();
    this.memory = record;
    return record;
  }

  private clearStored(): void {
    if (!this.store) return;
    const now = this.now();
    for (const k of STORED_KEYS) {
      // "" is this table's delete signal (see Store.saveSetting).
      try {
        this.store.saveSetting(k, "", now);
      } catch {
        // Best effort: a failed delete must not block switching keys.
      }
    }
  }

  /**
   * Stops injecting. The process falls back to the environment and the SDK
   * default chain, which is also what a fresh checkout does.
   */
  clear(): void {
    this.memory = null;
    this.clearStored();
  }

  /**
   * Resolves a local `aws` profile through the SDK's own shared config chain —
   * SSO, assume-role and a plain key file all included — and injects the
   * concrete credentials it produced.
   *
   * Deliberately not left to the SDK's default provider: that chain hands back
   * an opaque provider, and the point here is to *show* the operator which key
   * and which expiry they are running on.
   */
  async importProfile(profile: string, persist: boolean): Promise<Injected> {
    const name = profile.trim() || defaultProfile();
    if (!PROFILE_SHAPE.test(name)) {
      throw new Error(`프로파일 이름에 쓸 수 없는 문자가 있습니다: ${name}`);
    }
    const resolved = await resolveProfile(name);
    return this.set({ ...resolved, origin: "cli", profile: name, persist });
  }

  /** Re-reads the profile behind an existing import, one flight at a time. */
  private refreshFromProfile(current: Injected): Promise<Injected> {
    if (this.refreshing) return this.refreshing;
    const flight = (async () => {
      // Another caller may have refreshed while this one waited.
      const latest = this.injected();
      if (latest) {
        const left = expiresInMs(latest.expiration, this.now());
        if (left === null || left >= REFRESH_MARGIN_MS) return latest;
      }
      const name = current.profile || defaultProfile();
      const resolved = await resolveProfile(name);
      return this.set({ ...resolved, origin: "cli", profile: name, persist: current.persisted });
    })();
    this.refreshing = flight;
    return flight.finally(() => {
      this.refreshing = null;
    });
  }

  /**
   * The credential provider handed to every SDK client, or undefined to leave
   * the SDK's own chain in charge.
   *
   * A provider function rather than a fixed value: temporary keys expire, and
   * the SDK re-invokes the provider once `expiration` passes. That is what makes
   * an `aws sso login` session keep working after the dashboard has been running
   * for hours — the token is re-read from the profile instead of the whole
   * process failing with InvalidClientTokenId.
   */
  provider(): AwsCredentialIdentityProvider | undefined {
    if (!this.injected()) return undefined;
    return async (): Promise<AwsCredentialIdentity> => {
      let current = this.injected();
      if (!current) throw new Error("주입된 AWS 자격증명이 없습니다.");

      const left = expiresInMs(current.expiration, this.now());
      if (left !== null && left < REFRESH_MARGIN_MS) {
        if (current.origin === "cli") {
          current = await this.refreshFromProfile(current);
        } else if (left <= 0) {
          throw new Error(
            "주입된 임시 자격증명이 만료되었습니다 — 설정 탭에서 세션을 다시 불러오거나 키를 다시 붙여넣으세요.",
          );
        }
      }

      // AwsCredentialIdentity is readonly, so the optional fields are built
      // into the literal rather than assigned after — an absent sessionToken
      // must stay absent, not become undefined, or the SDK signs with it.
      const exp = parseExpiration(current.expiration);
      const out: AwsCredentialIdentity = {
        accessKeyId: current.accessKeyId,
        secretAccessKey: current.secretAccessKey,
        ...(current.sessionToken ? { sessionToken: current.sessionToken } : {}),
        ...(exp ? { expiration: exp } : {}),
      };
      return out;
    };
  }

  /**
   * What the 설정 screen draws. Masked throughout — the secret and the session
   * token never leave the server, in either direction.
   */
  view(nowMs: number): CredentialsView {
    const inj = this.injected();
    const env = envCredentials();

    let source: CredentialsView["source"] = "chain";
    let shown: ParsedCredentials = env;
    let origin: CredentialOrigin | null = null;
    let expires: number | null = null;
    let profile = "";
    let expiration = "";
    let persisted = false;

    if (inj) {
      source = "screen";
      shown = inj;
      origin = inj.origin;
      profile = inj.profile;
      expiration = inj.expiration;
      persisted = inj.persisted;
      expires = expiresInMs(inj.expiration, nowMs);
    } else if (isComplete(env)) {
      source = "env";
    }

    return {
      source,
      origin,
      persisted,
      profile,
      accessKeyIdMasked: maskKeyId(shown.accessKeyId),
      secretMasked: maskSecret(shown.secretAccessKey),
      hasSessionToken: shown.sessionToken !== "",
      temporary: isTemporary(shown),
      expiration,
      expiresInMs: expires,
      envAccessKeyIdMasked: maskKeyId(env.accessKeyId),
      defaultProfile: defaultProfile(),
    };
  }
}

/**
 * The load-and-retrieve half, kept separate so the refresh path does not recurse
 * through set().
 *
 * fromIni reads the shared config/credentials files only — unlike Go's
 * LoadDefaultConfig it never falls back to the process environment, so an
 * environment key cannot be imported under a profile's name by accident.
 */
async function resolveProfile(name: string): Promise<ParsedCredentials> {
  let got: AwsCredentialIdentity;
  try {
    got = await fromIni({ profile: name })();
  } catch (e) {
    const detail = (e as Error).message;
    throw new Error(
      `프로파일 "${name}" 의 세션을 읽지 못했습니다: ${detail} — 만료된 SSO 세션이면 \`aws sso login --profile ${name}\` 로 다시 로그인하세요`,
    );
  }
  const out: ParsedCredentials = {
    accessKeyId: got.accessKeyId ?? "",
    secretAccessKey: got.secretAccessKey ?? "",
    sessionToken: got.sessionToken ?? "",
    expiration: got.expiration ? got.expiration.toISOString() : "",
  };
  if (!isComplete(out)) {
    throw new Error(`프로파일 "${name}" 가 자격증명을 내놓지 않았습니다`);
  }
  return out;
}
