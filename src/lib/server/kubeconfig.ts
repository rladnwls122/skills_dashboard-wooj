import "server-only";
import { KubeConfig } from "@kubernetes/client-node";
import { findExecutable } from "./awslogin";

interface ExecConfig {
  command?: string;
  args?: string[];
}

// eksctl writes `command: aws` into the kubeconfig, and client-node's ExecAuth
// spawns it with child_process.spawn — no shell, no PATH fix-up. So every k8s
// panel dies as "spawn aws ENOENT" whenever the process PATH lacks the CLI,
// which on Windows is the normal case: the installer edits the *machine* PATH
// and a shell opened before that never sees it. The credentials are fine; only
// the lookup is broken, so the command is resolved to an absolute path here —
// the same lookup the 설정 screen uses to read the local session.
function resolveExecCommand(exec: ExecConfig | undefined): void {
  const command = exec?.command;
  if (!exec || !command || command.includes("/") || command.includes("\\")) return;

  const bin = findExecutable(command);
  if (!bin) {
    throw new Error(
      `kubeconfig 의 인증 명령 "${command}" 을(를) 찾지 못했습니다 — PATH 에 추가하거나 ` +
        `~/.kube/config 의 users[].user.exec.command 를 전체 경로로 바꾸세요.`,
    );
  }
  // A .cmd/.bat shim cannot be spawned directly on Windows since Node 20.12
  // (EINVAL) and ExecAuth passes no shell option, so those route through
  // cmd.exe. Everything quoted: Program Files has a space in it.
  if (/\.(cmd|bat)$/i.test(bin)) {
    const line = [bin, ...(exec.args ?? [])].map((a) => `"${a}"`).join(" ");
    exec.command = process.env.ComSpec ?? "cmd.exe";
    exec.args = ["/d", "/s", "/c", line];
    return;
  }
  exec.command = bin;
}

let cached: KubeConfig | null = null;

// Single loader for every k8s consumer (k8s.ts, resources.ts, …). Loading a
// KubeConfig per module was how the metrics panels ended up bypassing the exec
// fix above and failing alone with "spawn aws ENOENT".
export function kubeConfig(): KubeConfig {
  if (!cached) {
    const kc = new KubeConfig();
    if (process.env.KUBERNETES_SERVICE_HOST) {
      kc.loadFromCluster();
    } else {
      kc.loadFromDefault();
      const user = kc.getCurrentUser();
      resolveExecCommand(user?.exec ?? user?.authProvider?.config?.exec);
    }
    cached = kc;
  }
  return cached;
}
