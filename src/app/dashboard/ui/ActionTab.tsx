"use client";

import { useEffect, useState } from "react";
import {
  listDeployHistoryAction,
  patchDeploymentAction,
  verifyActionAction,
} from "@/app/actions/dashboard";
import type { DeployChangeEntry, KubePanel, VerificationResult } from "@/lib/types";
import { Card, ErrorNote, fmtTs, usePoll, type PollState } from "./shared";

export function ActionTab({ kube }: { kube: PollState<KubePanel> }) {
  const deployments = kube.data?.deployments ?? [];
  const [selected, setSelected] = useState("");
  const [replicas, setReplicas] = useState("");
  const [containerName, setContainerName] = useState("");
  const [cpuLimit, setCpuLimit] = useState("");
  const [memLimit, setMemLimit] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [verifications, setVerifications] = useState<Record<number, VerificationResult>>({});

  const history: PollState<DeployChangeEntry[]> = usePoll(listDeployHistoryAction, 15_000);

  const dep = deployments.find((d) => d.name === selected);
  const container = dep?.containers.find((c) => c.name === containerName) ?? dep?.containers[0];

  useEffect(() => {
    if (dep && !dep.containers.some((c) => c.name === containerName)) {
      setContainerName(dep.containers[0]?.name ?? "");
    }
  }, [dep, containerName]);

  const hasChange =
    (replicas !== "" && Number(replicas) !== dep?.replicas) ||
    (cpuLimit !== "" && cpuLimit !== container?.cpuLimit) ||
    (memLimit !== "" && memLimit !== container?.memLimit);

  const runPatch = async (): Promise<void> => {
    if (!dep) return;
    setBusy(true);
    setMessage(null);
    setConfirming(false);
    const res = await patchDeploymentAction({
      namespace: dep.namespace,
      name: dep.name,
      replicas: replicas !== "" ? Number(replicas) : undefined,
      containerName: cpuLimit !== "" || memLimit !== "" ? (container?.name ?? "") : undefined,
      cpuLimit: cpuLimit !== "" ? cpuLimit : undefined,
      memLimit: memLimit !== "" ? memLimit : undefined,
    });
    if (res.ok) {
      setMessage(
        `패치 성공 (이력 #${res.data.historyId}) — 약 2분 후 사후 검증 실행 가능. 자동 검증 타이머 시작.`,
      );
      history.refresh();
      const historyId = res.data.historyId;
      setTimeout(() => void runVerify(historyId), 125_000);
    } else {
      setMessage(`패치 실패: ${res.error}`);
    }
    setBusy(false);
  };

  const runVerify = async (historyId: number): Promise<void> => {
    const res = await verifyActionAction(historyId);
    if (res.ok) {
      setVerifications((prev) => ({ ...prev, [historyId]: res.data }));
      history.refresh();
    } else {
      setMessage(`검증 실패: ${res.error}`);
    }
  };

  const VERDICT_COLOR: Record<string, string> = {
    IMPROVED: "text-emerald-400",
    NO_CHANGE: "text-neutral-400",
    DEGRADED: "text-red-400",
    INCONCLUSIVE: "text-amber-400",
    PENDING: "text-neutral-500",
  };

  return (
    <div className="space-y-3">
      {message && (
        <div className="rounded border border-sky-900 bg-sky-950/40 px-3 py-2 text-xs text-sky-200">
          {message}
        </div>
      )}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card title="Deployment 조정" right={<ErrorNote error={kube.error} />}>
          <div className="space-y-2 text-xs">
            <label className="block">
              <span className="text-neutral-500">Deployment</span>
              <select
                value={selected}
                onChange={(e) => setSelected(e.target.value)}
                className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 px-2 py-1.5"
              >
                <option value="">선택</option>
                {deployments.map((d) => (
                  <option key={d.name} value={d.name}>
                    {d.namespace}/{d.name}
                  </option>
                ))}
              </select>
            </label>
            {dep && (
              <>
                <label className="block">
                  <span className="text-neutral-500">Container</span>
                  <select
                    value={container?.name ?? ""}
                    onChange={(e) => setContainerName(e.target.value)}
                    className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 px-2 py-1.5"
                  >
                    {dep.containers.map((c) => (
                      <option key={c.name} value={c.name}>
                        {c.name}
                      </option>
                    ))}
                  </select>
                </label>
                <div className="grid grid-cols-3 gap-2">
                  <label className="block">
                    <span className="text-neutral-500">Replicas</span>
                    <input
                      value={replicas}
                      onChange={(e) => setReplicas(e.target.value)}
                      placeholder={String(dep.replicas)}
                      className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 px-2 py-1.5"
                    />
                  </label>
                  <label className="block">
                    <span className="text-neutral-500">CPU Limit</span>
                    <input
                      value={cpuLimit}
                      onChange={(e) => setCpuLimit(e.target.value)}
                      placeholder={container?.cpuLimit ?? "예: 500m"}
                      className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 px-2 py-1.5"
                    />
                  </label>
                  <label className="block">
                    <span className="text-neutral-500">Memory Limit</span>
                    <input
                      value={memLimit}
                      onChange={(e) => setMemLimit(e.target.value)}
                      placeholder={container?.memLimit ?? "예: 256Mi"}
                      className="mt-1 w-full rounded border border-neutral-700 bg-neutral-900 px-2 py-1.5"
                    />
                  </label>
                </div>

                {hasChange && (
                  <div className="rounded border border-neutral-700 bg-neutral-950 p-2">
                    <div className="mb-1 font-semibold text-neutral-300">변경 전 / 후 비교</div>
                    <table className="w-full text-[11px]">
                      <thead className="text-neutral-500">
                        <tr>
                          <th className="text-left font-medium">항목</th>
                          <th className="text-left font-medium">현재</th>
                          <th className="text-left font-medium">변경 후</th>
                        </tr>
                      </thead>
                      <tbody className="text-neutral-300">
                        <tr>
                          <td>Replicas</td>
                          <td>{dep.replicas}</td>
                          <td className={replicas !== "" && Number(replicas) !== dep.replicas ? "font-bold text-amber-300" : ""}>
                            {replicas !== "" ? replicas : dep.replicas}
                          </td>
                        </tr>
                        <tr>
                          <td>CPU Limit ({container?.name})</td>
                          <td>{container?.cpuLimit}</td>
                          <td className={cpuLimit !== "" ? "font-bold text-amber-300" : ""}>
                            {cpuLimit !== "" ? cpuLimit : container?.cpuLimit}
                          </td>
                        </tr>
                        <tr>
                          <td>Memory Limit ({container?.name})</td>
                          <td>{container?.memLimit}</td>
                          <td className={memLimit !== "" ? "font-bold text-amber-300" : ""}>
                            {memLimit !== "" ? memLimit : container?.memLimit}
                          </td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                )}

                {!confirming ? (
                  <button
                    type="button"
                    disabled={!hasChange || busy}
                    onClick={() => setConfirming(true)}
                    className="rounded bg-amber-900/70 px-4 py-1.5 font-semibold text-amber-100 hover:bg-amber-900 disabled:opacity-40"
                  >
                    변경 적용…
                  </button>
                ) : (
                  <div className="rounded border border-red-900 bg-red-950/40 p-2">
                    <p className="text-red-200">
                      실제 클러스터의 {dep.namespace}/{dep.name} 을 JSON Patch로 변경합니다. 진행?
                    </p>
                    <div className="mt-2 flex gap-2">
                      <button
                        type="button"
                        disabled={busy}
                        onClick={() => void runPatch()}
                        className="rounded bg-red-700 px-3 py-1 font-semibold text-white hover:bg-red-600 disabled:opacity-50"
                      >
                        승인 및 패치
                      </button>
                      <button
                        type="button"
                        onClick={() => setConfirming(false)}
                        className="rounded bg-neutral-800 px-3 py-1 text-neutral-300"
                      >
                        취소
                      </button>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        </Card>

        <Card title="현재 Deployment 구성">
          <div className="space-y-2 text-[11px]">
            {deployments.map((d) => (
              <div key={d.name} className="rounded border border-neutral-800 bg-neutral-950 p-2">
                <div className="flex justify-between">
                  <span className="font-semibold text-neutral-200">
                    {d.namespace}/{d.name}
                  </span>
                  <span
                    className={`tabular-nums ${d.readyReplicas >= d.replicas ? "text-emerald-400" : "text-amber-400"}`}
                  >
                    ready {d.readyReplicas}/{d.replicas} (updated {d.updatedReplicas})
                  </span>
                </div>
                {d.containers.map((c) => (
                  <div key={c.name} className="mt-1 text-neutral-400">
                    {c.name}: CPU {c.cpuRequest}/{c.cpuLimit} · Mem {c.memRequest}/{c.memLimit}
                    <span className="ml-2 text-neutral-600">{c.image}</span>
                  </div>
                ))}
              </div>
            ))}
            {deployments.length === 0 && <div className="text-neutral-500">Deployment 없음</div>}
          </div>
        </Card>
      </div>

      <Card title="변경 이력 + 사후 검증">
        <div className="space-y-2 text-[11px]">
          {(history.data ?? []).map((h) => {
            const v = verifications[h.id];
            return (
              <div key={h.id} className="rounded border border-neutral-800 bg-neutral-950 p-2">
                <div className="flex items-center justify-between">
                  <div>
                    <span className="text-neutral-500">{fmtTs(h.ts)}</span>{" "}
                    <span className="text-neutral-200">
                      {h.namespace}/{h.name}
                    </span>{" "}
                    <span className="text-neutral-400">{h.change}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={`font-bold ${VERDICT_COLOR[v?.verdict ?? h.verdict] ?? ""}`}>
                      {v?.verdict ?? h.verdict}
                    </span>
                    <button
                      type="button"
                      onClick={() => void runVerify(h.id)}
                      className="rounded bg-neutral-800 px-2 py-0.5 text-neutral-300 hover:bg-neutral-700"
                    >
                      지금 검증
                    </button>
                  </div>
                </div>
                {v && (
                  <ul className="mt-1 list-inside list-disc text-neutral-500">
                    {v.details.map((d, i) => (
                      <li key={i}>{d}</li>
                    ))}
                  </ul>
                )}
              </div>
            );
          })}
          {(history.data?.length ?? 0) === 0 && (
            <div className="text-neutral-500">변경 이력 없음</div>
          )}
        </div>
      </Card>
    </div>
  );
}
