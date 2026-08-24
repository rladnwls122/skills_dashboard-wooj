// Finding an executable rather than asking the shell to.
//
// The obvious implementation — spawn "aws" and see what happens — cannot tell
// "no CLI installed" from "the CLI failed": a shell reports both as exit 1, with
// a message in the console's OEM codepage that arrives as mojibake. The
// difference matters, because one is fixed by pasting keys and the other by
// running `aws sso login`. So the lookup is done here, where the answer is a
// path or nothing.
//
// The kubeconfig exec plugin has the same problem from the other side:
// @kubernetes/client-node spawns `command: aws` with no shell, so a PATH without
// the CLI is a bare "spawn aws ENOENT".

import fs from "node:fs";
import path from "node:path";

// Where the AWS CLI installs itself when it is not on PATH. Worth checking: on
// Windows the installer adds the directory to the *machine* PATH, which a server
// started from a shell opened beforehand does not have.
const EXTRA_DIRS =
  process.platform === "win32"
    ? ["C:\\Program Files\\Amazon\\AWSCLIV2", "C:\\Program Files (x86)\\Amazon\\AWSCLIV2"]
    : ["/usr/local/bin", "/opt/homebrew/bin"];

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
