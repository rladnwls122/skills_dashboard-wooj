// Reading AWS credentials out of whatever the operator has in hand.
//
// Under time pressure the keys arrive in whatever shape the source produced —
// a CloudShell `export` block, the console's "명령줄 액세스" panel, an .env
// fragment, a `~/.aws/credentials` section, the JSON that
// `aws configure export-credentials` prints. Asking someone to retype three
// values into three boxes is how a session token ends up truncated, so the
// screen takes the blob and picks the fields out of it.
//
// Pure and client-safe on purpose: no AWS SDK, no filesystem, no `server-only`.
// The server reuses the same functions for the `aws` CLI import, so the parser
// that the tests cover is the parser that runs in both places.

export interface ParsedCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  // ISO-8601 as printed by `aws configure export-credentials`, when present.
  expiration: string;
}

const EMPTY: ParsedCredentials = {
  accessKeyId: "",
  secretAccessKey: "",
  sessionToken: "",
  expiration: "",
};

// An access key id is the one field with a recognisable shape: AKIA for a long
// lived user key, ASIA for a temporary (session) one.
const KEY_ID_SHAPE = /\b((?:AKIA|ASIA)[0-9A-Z]{12,})\b/;

// `aws_secret_access_key`, `SecretAccessKey`, `secret-access-key` — the same
// field in four notations. Anchored on the distinguishing word of each so that
// `aws_secret_access_key` cannot also satisfy the access-key-id pattern (it
// carries no "id").
const FIELD_PATTERNS: { field: keyof ParsedCredentials; re: RegExp }[] = [
  { field: "accessKeyId", re: /(?:aws[_-]?)?access[_-]?key[_-]?id/i },
  { field: "secretAccessKey", re: /(?:aws[_-]?)?secret[_-]?access[_-]?key/i },
  { field: "sessionToken", re: /(?:aws[_-]?)?(?:session|security)[_-]?token/i },
  { field: "expiration", re: /^expiration$/i },
];

// Strips the shell/PowerShell/cmd/JSON scaffolding around `NAME = VALUE`.
function splitAssignment(line: string): { name: string; value: string } | null {
  let s = line.trim();
  if (s === "" || s.startsWith("#") || s.startsWith(";") || s.startsWith("[")) return null;
  // `export FOO=..`, `set FOO=..`, `setx FOO ..`, `$Env:FOO=..`, `$env:FOO=..`
  s = s.replace(/^(?:export|set|setx)\s+/i, "").replace(/^\$env:/i, "");
  const m = /^["']?([A-Za-z_][A-Za-z0-9_-]*)["']?\s*[:=]\s*(.*)$/.exec(s);
  if (!m) return null;
  let value = m[2]!.trim();
  // Trailing JSON punctuation, then surrounding quotes.
  value = value.replace(/[,;]\s*$/, "").trim();
  value = value.replace(/^(["'])([\s\S]*)\1$/, "$2");
  return { name: m[1]!, value: value.trim() };
}

// Extracts whatever of the four fields the text contains. Anything it does not
// recognise is ignored rather than rejected — a blob usually carries a profile
// header, a region, an expiry note and a blank line as well.
export function parseCredentialBlob(text: string): ParsedCredentials {
  const out: ParsedCredentials = { ...EMPTY };
  for (const rawLine of text.split(/\r?\n/)) {
    // A JSON blob arrives on one line as often as on five.
    for (const piece of rawLine.split(/(?<=[,{])\s*(?=")/)) {
      const kv = splitAssignment(piece.replace(/^[{}\s]+|[{}\s]+$/g, ""));
      if (!kv || kv.value === "") continue;
      for (const { field, re } of FIELD_PATTERNS) {
        if (out[field] === "" && re.test(kv.name)) {
          out[field] = kv.value;
          break;
        }
      }
    }
  }

  // A bare key pasted on its own — no name, no assignment. Worth catching: it
  // is what someone reads off a screen when only the id is in question.
  if (out.accessKeyId === "") {
    const m = KEY_ID_SHAPE.exec(text);
    if (m) out.accessKeyId = m[1]!;
  }
  return out;
}

// One `[profile]` section of a shared credentials/config file. The file is the
// fallback path for `aws configure export-credentials`, which older CLI builds
// do not have — a session obtained by `aws sso login`/`aws configure` still
// lands here as `aws_session_token`.
export function parseSharedCredentialsFile(text: string, profile: string): ParsedCredentials {
  const want = profile.replace(/^profile\s+/, "").trim() || "default";
  let inSection = false;
  const lines: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    const header = /^\s*\[([^\]]+)\]\s*$/.exec(line);
    if (header) {
      const name = header[1]!.replace(/^profile\s+/, "").trim();
      inSection = name === want;
      continue;
    }
    if (inSection) lines.push(line);
  }
  return parseCredentialBlob(lines.join("\n"));
}

export function isComplete(c: ParsedCredentials): boolean {
  return c.accessKeyId !== "" && c.secretAccessKey !== "";
}

// A temporary key (ASIA…) without its session token is not usable, and the
// resulting error — InvalidClientTokenId — names nothing about the missing
// field. Caught here so the screen can say it before the call is made.
export function credentialProblem(c: ParsedCredentials): string | null {
  if (c.accessKeyId === "" && c.secretAccessKey === "") return "붙여넣은 값에서 키를 찾지 못했습니다.";
  if (c.accessKeyId === "") return "Access Key ID 가 비어 있습니다.";
  if (c.secretAccessKey === "") return "Secret Access Key 가 비어 있습니다.";
  if (/^ASIA/i.test(c.accessKeyId) && c.sessionToken === "") {
    return "ASIA 로 시작하는 임시 키인데 Session Token 이 없습니다 — 세 값을 함께 넣어야 합니다.";
  }
  return null;
}

// Enough of the id to recognise which key is in force, never enough to use it.
export function maskKeyId(value: string): string {
  if (value === "") return "";
  if (value.length <= 8) return `${value.slice(0, 2)}••••`;
  return `${value.slice(0, 4)}••••${value.slice(-4)}`;
}

// The secret and the session token are shown as length only. There is no
// version of "part of the secret" that is safe to put on a screen someone may
// be sharing.
export function maskSecret(value: string): string {
  return value === "" ? "" : `•••••••• (${value.length}자)`;
}

// Milliseconds left on a temporary credential, or null when it does not expire
// (a long-lived user key) or the timestamp is unreadable.
export function expiresInMs(expiration: string, nowMs: number): number | null {
  if (expiration === "") return null;
  const t = Date.parse(expiration);
  if (!Number.isFinite(t)) return null;
  return t - nowMs;
}
