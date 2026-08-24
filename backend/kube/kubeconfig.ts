// In-cluster config when running in a pod, kubeconfig otherwise. One loader for
// every Kubernetes consumer: loading a KubeConfig per module was how the metrics
// panels ended up bypassing the exec fix below and failing alone with
// "spawn aws ENOENT".

import { KubeConfig } from "@kubernetes/client-node";

import { findExecutable } from "./exec.ts";

interface ExecConfig {
  command?: string;
  args?: string[];
  env?: ExecEnvironmentEntry[];
}

/**
 * One environment variable handed to the exec-auth plugin. The shape
 * @kubernetes/client-node reads out of `users[].user.exec.env`: it merges these
 * over a copy of process.env before spawning, which is the only supported way to
 * put a value in front of the child without editing this process's own
 * environment.
 */
export interface ExecEnvironmentEntry {
  name: string;
  value: string;
}

// eksctl writes `command: aws` into the kubeconfig, and client-node's ExecAuth
// spawns it with child_process.spawn — no shell, no PATH fix-up. So every k8s
// panel dies as "spawn aws ENOENT" whenever the process PATH lacks the CLI,
// which on Windows is the normal case: the installer edits the *machine* PATH
// and a shell opened before that never sees it. The credentials are fine; only
// the lookup is broken, so the command is resolved to an absolute path here.
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
/**
 * The `env` list the kubeconfig file itself declared, before anything was
 * injected over it. Kept so a second injection replaces the first rather than
 * stacking on it, and so clearing the injection puts the file's own value back.
 */
let fileExecEnvironment: ExecEnvironmentEntry[] = [];

function currentExec(kc: KubeConfig): ExecConfig | undefined {
  const user = kc.getCurrentUser() as
    | { exec?: ExecConfig; authProvider?: { config?: { exec?: ExecConfig } } }
    | null;
  return user?.exec ?? user?.authProvider?.config?.exec;
}

/**
 * Puts the credentials the 설정 screen injected in front of the exec plugin.
 *
 * Without this, injecting keys fixed the AWS panels and left Kubernetes broken
 * forever: the SDK clients take a credential provider, but `aws eks get-token`
 * is a child process that client-node spawns with the *inherited* process.env,
 * so it kept signing with whatever the server was started with — or with
 * nothing. The operator saw AWS recover, assumed the injection had worked, and
 * had no way to reach the one consumer it had not reached.
 *
 * The session token is written even when it is empty on purpose: an injected
 * permanent key combined with a stale AWS_SESSION_TOKEN left over in the parent
 * environment is signed as an expired session, which fails as
 * InvalidClientTokenId and reads like a bad key.
 */
function applyExecEnvironment(kc: KubeConfig, injected: ExecEnvironmentEntry[]): void {
  const exec = currentExec(kc);
  // In-cluster (a ServiceAccount token) and certificate users have no exec
  // plugin at all — there is nothing to hand an environment to.
  if (!exec) return;
  if (injected.length === 0) {
    if (fileExecEnvironment.length > 0) exec.env = [...fileExecEnvironment];
    else delete exec.env;
    return;
  }
  const overridden = new Set(injected.map((e) => e.name));
  exec.env = [...fileExecEnvironment.filter((e) => !overridden.has(e.name)), ...injected];
}

export function kubeConfig(injected: ExecEnvironmentEntry[] = []): KubeConfig {
  if (!cached) {
    const kc = new KubeConfig();
    if (process.env.KUBERNETES_SERVICE_HOST) {
      kc.loadFromCluster();
    } else {
      kc.loadFromDefault();
      resolveExecCommand(currentExec(kc));
      fileExecEnvironment = [...(currentExec(kc)?.env ?? [])];
    }
    cached = kc;
  }
  // Re-applied on every call, not only at construction: the injected keys can
  // change while the process runs, and a KubeConfig that survived the change
  // would otherwise keep spawning the CLI with the previous identity.
  applyExecEnvironment(cached, injected);
  return cached;
}

/**
 * Throws the loaded KubeConfig away.
 *
 * Called when credentials or settings change. Dropping it matters for more than
 * the exec environment: client-node's ExecAuth memoises the token it got from
 * `aws eks get-token` inside the KubeConfig's own auth provider until that
 * token's expiry, so a KubeConfig that outlives a credential change keeps
 * presenting a bearer token minted by the identity the operator just replaced.
 * A fresh KubeConfig has an empty token cache, which is the only way to make
 * re-injecting actually take effect.
 */
export function resetKubeConfig(): void {
  cached = null;
  fileExecEnvironment = [];
}
