// Everything this service cannot answer from its own SQLite file: AWS reads
// (CloudWatch, Logs Insights, WAFv2, ELBv2, EKS), Kubernetes reads and writes,
// and the WAFv2 rule engine that the sandbox evaluates against.
//
// An interface with one implementation on purpose. The routes and the local
// state are the deliverable here; the cloud reads are a separate,
// credential-holding concern, and keeping them behind this seam means the HTTP
// surface can be run, tested and pointed at by the UI without a single call
// leaving the machine.

import type {
  AssembledRule,
  CountEvidence,
  CredentialCheck,
  CredentialsView,
  DeploymentInfo,
  DiscoveryResult,
  GradingPanel,
  IncidentContextResult,
  KubePanel,
  MetricsPanel,
  NodeCountProjection,
  PodLogsResult,
  RequestLogQueryResult,
  ResolvedWindow,
  RuleTestResult,
  WafLogQueryResult,
  WafPanel,
  WafSampleRow,
  WindowSelection,
} from "../../src/lib/types.ts";
import type { WafRuleUpdateResult } from "../types/types.ts";

// --- request payloads --------------------------------------------------------

export interface PodLogsParams {
  pod: string;
  container: string;
  previous: boolean;
  tailLines: number;
  window?: WindowSelection | null;
}

export interface RequestLogParams {
  statusClass: string;
  pathContains: string;
  window?: WindowSelection | null;
}

export interface DeploymentPatchRequest {
  namespace: string;
  name: string;
  replicas?: number;
  containerName?: string;
  cpuLimit?: string;
  memLimit?: string;
}

export interface RuleTestParams {
  ruleJson: string;
  requests: import("../../src/lib/types.ts").TestRequest[];
}

/** The WAF log table's filter: "ALL" | "BLOCK" | "ALLOW" | "COUNT" and a path substring. */
export interface WafLogParams {
  action: string;
  pathContains: string;
  window?: WindowSelection | null;
}

/**
 * Typed in, or pasted as a blob — an `export` block, an .env fragment, a
 * `~/.aws/credentials` section, the JSON the CLI prints. The three fields win
 * over the blob when both are given.
 */
export interface CredentialsInput {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  blob: string;
  /** false (the default) keeps the keys in this process's memory only. */
  persist: boolean;
}

export interface ImportCredentialsInput {
  profile: string;
  persist: boolean;
}

export interface Provider {
  /**
   * Drops anything the provider memoized against the previous settings (SDK
   * clients capture a region at construction). Called on settings save.
   */
  reset(): void;
  kubePanel(): Promise<KubePanel>;
  metricsPanel(win: ResolvedWindow): Promise<MetricsPanel>;
  wafPanel(win: ResolvedWindow): Promise<WafPanel>;
  wafSamples(): Promise<WafSampleRow[]>;
  gradingPanel(win: ResolvedWindow): Promise<GradingPanel>;
  podLogs(p: PodLogsParams, win: ResolvedWindow): Promise<PodLogsResult>;
  requestLogRows(p: RequestLogParams, win: ResolvedWindow): Promise<RequestLogQueryResult>;
  deployment(namespace: string, name: string): Promise<DeploymentInfo>;
  patchDeployment(req: DeploymentPatchRequest): Promise<DeploymentInfo>;
  discover(kind: string): Promise<DiscoveryResult>;
  assembleRule(kind: string, win: ResolvedWindow): Promise<AssembledRule>;
  testRule(p: RuleTestParams): Promise<RuleTestResult>;
  incidentContext(): Promise<IncidentContextResult>;
  updateWafRule(
    ruleJson: string,
    action: string | null,
    win: ResolvedWindow,
  ): Promise<WafRuleUpdateResult>;
  countEvidence(ruleName: string, win: ResolvedWindow): Promise<CountEvidence>;
  wafLogRows(p: WafLogParams, win: ResolvedWindow): Promise<WafLogQueryResult>;
  nodeCost(): Promise<NodeCountProjection>;

  // Credentials are a provider concern for the same reason the reads are: they
  // are the thing that makes a cloud call possible, and a build with no cloud
  // layer wired up has nothing to inject them into.
  credentialsView(nowMs: number): CredentialsView;
  saveCredentials(input: CredentialsInput): Promise<void>;
  importCredentials(input: ImportCredentialsInput): Promise<void>;
  clearCredentials(): Promise<void>;
  checkCredentials(): Promise<CredentialCheck>;
}

/**
 * What every unported capability returns. It is a plain failed ActionResult on
 * the wire, which is exactly what the UI already renders for an AWS call that
 * did not work.
 */
export const ERR_UNAVAILABLE = "연동 미구성";

function unavailable(what: string): Error {
  return new Error(
    `${what}: ${ERR_UNAVAILABLE} — 이 백엔드는 로컬 상태(SQLite·설정·샌드박스 데이터·점검)만 제공합니다`,
  );
}

/**
 * The default Provider: it makes no network calls at all and reports, per
 * capability, that it is not wired up.
 */
export class UnavailableProvider implements Provider {
  reset(): void {}

  kubePanel(): Promise<KubePanel> {
    return Promise.reject(unavailable("Kubernetes 패널"));
  }
  metricsPanel(): Promise<MetricsPanel> {
    return Promise.reject(unavailable("CloudWatch 지표 패널"));
  }
  wafPanel(): Promise<WafPanel> {
    return Promise.reject(unavailable("WAF 패널"));
  }
  wafSamples(): Promise<WafSampleRow[]> {
    return Promise.reject(unavailable("WAF 샘플 요청"));
  }
  gradingPanel(): Promise<GradingPanel> {
    return Promise.reject(unavailable("채점 패널"));
  }
  podLogs(): Promise<PodLogsResult> {
    return Promise.reject(unavailable("Pod 로그"));
  }
  requestLogRows(): Promise<RequestLogQueryResult> {
    return Promise.reject(unavailable("요청 로그 조회"));
  }
  deployment(): Promise<DeploymentInfo> {
    return Promise.reject(unavailable("Deployment 조회"));
  }
  patchDeployment(): Promise<DeploymentInfo> {
    return Promise.reject(unavailable("Deployment 변경"));
  }
  discover(): Promise<DiscoveryResult> {
    return Promise.reject(unavailable("리소스 자동 탐색"));
  }
  assembleRule(): Promise<AssembledRule> {
    return Promise.reject(unavailable("규칙 자동 조립"));
  }
  testRule(): Promise<RuleTestResult> {
    return Promise.reject(unavailable("규칙 시뮬레이터"));
  }
  incidentContext(): Promise<IncidentContextResult> {
    return Promise.reject(unavailable("인시던트 컨텍스트"));
  }
  updateWafRule(): Promise<WafRuleUpdateResult> {
    return Promise.reject(unavailable("WAF 규칙 변경"));
  }
  countEvidence(): Promise<CountEvidence> {
    return Promise.reject(unavailable("WAF 차단 근거 분석"));
  }
  wafLogRows(): Promise<WafLogQueryResult> {
    return Promise.reject(unavailable("WAF 로그 조회"));
  }
  nodeCost(): Promise<NodeCountProjection> {
    return Promise.reject(unavailable("비용/노드 수 산출"));
  }
  credentialsView(): CredentialsView {
    throw unavailable("AWS 자격증명 조회");
  }
  saveCredentials(): Promise<void> {
    return Promise.reject(unavailable("AWS 자격증명 주입"));
  }
  importCredentials(): Promise<void> {
    return Promise.reject(unavailable("aws 프로파일 세션 불러오기"));
  }
  clearCredentials(): Promise<void> {
    return Promise.reject(unavailable("AWS 자격증명 해제"));
  }
  checkCredentials(): Promise<CredentialCheck> {
    return Promise.reject(unavailable("AWS 자격증명 확인"));
  }
}
