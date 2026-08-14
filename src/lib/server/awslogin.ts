import "server-only";

// Picking up the session the operator already logged into.
//
// The credentials in play during the exercise are temporary: `aws sso login`,
// `aws configure sso`, an assumed role, a console "명령줄 액세스" block. All of
// them produce an access key that expires, and the dashboard is a long-running
// process — so "it worked an hour ago" is the normal way for every panel to
// fail at once.
//
// Rather than have someone paste three values again every time, this reads the
// live session straight out of the local AWS CLI. `aws configure
// export-credentials` is the CLI's own answer to "what credentials would you
// use right now": it resolves the profile, refreshes an SSO token from the
// cache if it can, and prints the result — including the session token and its
// expiry. Older CLI builds do not have the subcommand, so a plain read of
// ~/.aws/credentials is kept as the fallback.
//
// Deliberately not the SDK's default provider chain: that chain hands back an
// opaque provider, and the point here is to *show* the operator which key and
// which expiry they are running on.

import { execFile } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  isComplete,
  parseCredentialBlob,
  parseSharedCredentialsFile,
  type ParsedCredentials,
} from "@/lib/awscreds";

export interface CliSession extends ParsedCredentials {
  // Which profile answered, and how it was read — both go on screen, because
  // "the wrong account" and "the wrong profile" look identical otherwise.
  profile: string;
  via: "aws configure export-credentials" | "~/.aws/credentials";
}

// A profile name reaches the CLI as an argument. Everything outside the shape
// AWS itself allows is refused rather than escaped — the value comes from a
// text box on a page with no login.
const PROFILE_SHAPE = /^[A-Za-z0-9_.@=+-]{1,128}$/;

function run(
  cmd: string,
  args: string[],
  timeoutMs: number,
  useShell = false,
): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout: timeoutMs, windowsHide: true, shell: useShell }, (err, stdout, stderr) => {
      if (err) {
        // The CLI puts the actionable half of the message on stderr ("Error
        // when retrieving token from sso: Token has expired"), so it is what
        // gets surfaced, not the exec wrapper's "Command failed".
        const detail = (stderr || stdout || err.message).trim();
        const e = new Error(detail) as Error & { code?: string };
        e.code = (err as NodeJS.ErrnoException).code;
        reject(e);
        return;
      }
      resolve(stdout);
    });
  });
}

export const NO_CLI = "aws CLI 를 찾지 못했습니다";

// Where the AWS CLI installs itself when it is not on PATH. Worth checking:
// on Windows the installer adds the directory to the *machine* PATH, which a
// dev server started from a shell opened beforehand does not have.
const EXTRA_DIRS =
  process.platform === "win32"
    ? ["C:\\Program Files\\Amazon\\AWSCLIV2", "C:\\Program Files (x86)\\Amazon\\AWSCLIV2"]
    : ["/usr/local/bin", "/opt/homebrew/bin"];

// Finding the binary rather than asking the shell to.
//
// The obvious implementation — spawn "aws" and see what happens — cannot tell
// "no CLI installed" from "the CLI failed": a shell reports both as exit 1,
// with a message in the console's OEM codepage that arrives as mojibake. The
// difference matters, because one is fixed by pasting keys and the other by
// running `aws sso login`. So the lookup is done here, where the answer is a
// path or nothing.
//
// Exported because the kubeconfig exec plugin has the same problem from the
// other side: @kubernetes/client-node spawns `command: aws` with no shell, so
// a PATH without the CLI is a bare "spawn aws ENOENT" (see server/k8s.ts).
export function findExecutable(name: string): string | null {
  const exts =
    process.platform === "win32"
      ? (process.env.PATHEXT ?? ".COM;.EXE;.BAT;.CMD").split(";").map((e) => e.toLowerCase())
      : [""];
  const dirs = [...(process.env.PATH ?? "").split(path.delimiter), ...EXTRA_DIRS];
  for (const dir of dirs) {
    if (dir === "") continue;
    for (const ext of exts) {
      const candidate = path.join(dir, `${name}${ext}`);
      try {
        if (fs.statSync(candidate).isFile()) return candidate;
      } catch {
        // Not there — the next candidate is the answer, not an error.
      }
    }
  }
  return null;
}

function findAwsCli(): string | null {
  return findExecutable("aws");
}

async function runAwsCli(args: string[], timeoutMs: number): Promise<string> {
  const bin = findAwsCli();
  if (!bin) throw new Error(`${NO_CLI} — 키를 직접 붙여넣으세요.`);
  // A .cmd/.bat shim cannot be spawned directly on Windows since Node 20.12
  // (EINVAL), so those go through a shell. The path is quoted because Program
  // Files has a space in it; the arguments are literals except the profile,
  // which PROFILE_SHAPE has already restricted to characters a shell does
  // nothing with.
  if (/\.(cmd|bat)$/i.test(bin)) {
    return run(`"${bin}" ${args.join(" ")}`, [], timeoutMs, true);
  }
  return run(bin, args, timeoutMs);
}

function sharedCredentialsPath(): string {
  return (
    process.env.AWS_SHARED_CREDENTIALS_FILE ?? path.join(os.homedir(), ".aws", "credentials")
  );
}

export function activeProfile(): string {
  return process.env.AWS_PROFILE?.trim() || "default";
}

// The session the local CLI would use right now. Throws with a message that
// names the next command to run — an expired SSO token is the expected failure
// here, not an exceptional one.
export async function readCliSession(profileInput?: string): Promise<CliSession> {
  const profile = (profileInput?.trim() || activeProfile()).trim();
  if (!PROFILE_SHAPE.test(profile)) {
    throw new Error(`프로파일 이름에 쓸 수 없는 문자가 있습니다: ${profile}`);
  }

  const args = ["configure", "export-credentials", "--format", "process"];
  if (profile !== "default") args.push("--profile", profile);

  let cliError: string | null = null;
  try {
    // SSO token refresh is a network round trip; 20s is long enough for it and
    // short enough that a hung CLI does not hold the request open.
    const stdout = await runAwsCli(args, 20_000);
    const parsed = parseCredentialBlob(stdout);
    if (isComplete(parsed)) {
      return { ...parsed, profile, via: "aws configure export-credentials" };
    }
    cliError = "CLI 가 자격증명을 출력하지 않았습니다.";
  } catch (e) {
    cliError = e instanceof Error ? e.message : String(e);
  }

  // Fallback: the file the CLI writes. Covers builds older than the
  // export-credentials subcommand (AWS CLI < 2.9) and hosts with no CLI at all
  // but a credentials file copied in.
  const file = sharedCredentialsPath();
  try {
    const text = fs.readFileSync(file, "utf8");
    const parsed = parseSharedCredentialsFile(text, profile);
    if (isComplete(parsed)) {
      return { ...parsed, profile, via: "~/.aws/credentials" };
    }
  } catch {
    // No file, or unreadable — the CLI error below is the more useful one.
  }

  const suffix = profile === "default" ? "" : ` --profile ${profile}`;
  const hint = (cliError ?? "").includes(NO_CLI)
    ? " — 이 컴퓨터에는 aws CLI 가 없습니다. '키 직접 입력' 으로 붙여넣으세요."
    : /token has expired|sso|expired/i.test(cliError ?? "")
      ? ` — \`aws sso login${suffix}\` 로 다시 로그인한 뒤 눌러 주세요.`
      : ` — \`aws configure${suffix}\` 로 자격증명을 만든 뒤 눌러 주세요.`;
  throw new Error(`프로파일 "${profile}" 의 세션을 읽지 못했습니다: ${cliError ?? file}${hint}`);
}
