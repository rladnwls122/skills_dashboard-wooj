// Resolves every value the service runs on.
//
// Two sources, in order: an override saved on the settings screen (SQLite),
// then the process environment. Nothing here reads a file — main.ts folds .env
// into the environment at start (backend/config/dotenv.ts), so by the time this
// runs there is a single source to read.

import type {
  SettingSpec,
  SettingRow,
  SettingsView,
  SettingSource,
} from "../../src/lib/types.ts";
import type { Store } from "../store/store.ts";

/** Process-level configuration, read once at start. */
export interface ServerConfig {
  addr: string;
  dbPath: string;
  allowedOrigins: string;
}

function env(key: string, fallback: string): string {
  const v = (process.env[key] ?? "").trim();
  return v !== "" ? v : fallback;
}

export function loadServer(): ServerConfig {
  return {
    // Loopback by default: this is a single-operator tool holding AWS
    // credentials, so binding 0.0.0.0 has to be a deliberate act.
    addr: env("API_ADDR", "127.0.0.1:8787"),
    dbPath: env("DB_PATH", "./data/dashboard.db"),
    // The dev server runs on 3100 (see mise.toml).
    allowedOrigins: env("CORS_ALLOW_ORIGINS", "http://localhost:3100,http://127.0.0.1:3100"),
  };
}

/** Cache TTLs, in milliseconds. */
export const POLLING = {
  kubeTtl: 3_000,
  metricsTtl: 30_000,
  wafTtl: 30_000,
  logCacheTtl: 30_000,
  logFailTtl: 10_000,
  verificationDelay: 60_000,
};

// --- settings ---------------------------------------------------------------

/** The settings screen, in display order. */
export const SPECS: SettingSpec[] = [
  {
    key: "AWS_REGION",
    label: "AWS 리전",
    hint: "워크로드(ALB·RDS·EKS)가 있는 리전. WAF 가 CLOUDFRONT scope 면 WAF 만 us-east-1 로 자동 전환됩니다.",
    discover: null,
  },
  {
    key: "WAF_SCOPE",
    label: "WAF Scope",
    hint: "CLOUDFRONT 또는 REGIONAL. CloudFront 배포에 붙은 WebACL 은 CLOUDFRONT 이고 us-east-1 에서만 조회됩니다.",
    discover: null,
  },
  {
    key: "WAF_WEB_ACL_NAME",
    label: "WebACL 이름",
    hint: "규칙 목록과 샘플 요청을 읽는 대상.",
    discover: "webacl",
  },
  {
    key: "WAF_LOG_GROUP",
    label: "WAF 로그 그룹",
    hint: "비어 있으면 GetSampledRequests(규칙에 매칭된 요청만, 규칙당 500건)로 떨어집니다. 지정하면 선택 구간 전수 집계로 바뀌고 User-Agent 통계가 채워집니다.",
    discover: "waflog",
  },
  {
    key: "ALB_NAME",
    label: "ALB 이름",
    hint: "TargetResponseTime·상태코드 지표와 Target Group 자동 탐색의 기준.",
    discover: "alb",
  },
  {
    key: "EKS_CLUSTER_NAME",
    label: "EKS 클러스터",
    hint: "노드 스케일링 조회에 사용. 앱 로그 그룹 기본값도 이 이름에서 만들어집니다.",
    discover: "eks",
  },
  {
    key: "RDS_PROXY_NAME",
    label: "RDS Proxy 이름",
    hint: "AWS/RDS 지표의 ProxyName 차원 값.",
    discover: "rdsproxy",
  },
  {
    key: "APP_LOG_GROUP",
    label: "앱 로그 그룹",
    hint:
      "요청 로그·채점 지표 집계에 쓰는 CloudWatch Logs 그룹. EKS Container Insights 면 /aws/containerinsights/<클러스터>/application. 그룹이 여러 개로 나뉘면 쉼표로 나열. [GIN] 액세스 라인이 들어 있는 그룹이어야 한다.",
    discover: "loggroup",
  },
  {
    key: "TARGET_NAMESPACE",
    label: "Kubernetes 네임스페이스",
    hint: "Pod·Deployment·이벤트를 읽는 네임스페이스.",
    discover: null,
  },
  {
    key: "MAX_REPLICAS",
    label: "최대 replica",
    hint: "Deployment 조정 화면이 허용하는 상한.",
    discover: null,
  },
  {
    key: "MATCH_START",
    label: "경기 시작 시각",
    hint: "채점 창(경기 시작 +1h ~ +3h)의 기준. 로컬 시각으로 2026-08-14 09:00 또는 09:00 형태. 비워 두면 비용 패널이 평균을 만들지 않고 현재 대수만 보여줍니다.",
    discover: null,
  },
];

/**
 * Reads through the override table on every access. The table has ten rows, and
 * a cache here would need invalidating from the save path in a way that is easy
 * to get wrong — a setting that appears to save and then does not is the worst
 * outcome.
 */
export class Settings {
  private readonly store: Store | null;

  constructor(store: Store | null) {
    this.store = store;
  }

  private overrides(): Record<string, string> {
    // A missing or locked database must not take the dashboard down — the
    // environment still works.
    if (!this.store) return {};
    try {
      return this.store.loadSettings();
    } catch {
      return {};
    }
  }

  private builtin(key: string): string {
    switch (key) {
      case "AWS_REGION":
        return "ap-northeast-2";
      case "WAF_SCOPE":
        return "CLOUDFRONT";
      case "WAF_WEB_ACL_NAME":
        return "skills-waf";
      case "WAF_LOG_GROUP":
        return "";
      case "ALB_NAME":
        return "skills-alb";
      case "EKS_CLUSTER_NAME":
        return "skills-eks";
      case "RDS_PROXY_NAME":
        return "skills-db-proxy";
      case "APP_LOG_GROUP":
        // Depends on the cluster name, which is itself overridable.
        return "/aws/containerinsights/" + this.value("EKS_CLUSTER_NAME") + "/application";
      case "TARGET_NAMESPACE":
        return "default";
      case "MAX_REPLICAS":
        return "20";
      case "MATCH_START":
        // Deliberately empty. The scoring window is derived from this value,
        // and a guessed start time produces a time-weighted average that is
        // wrong in a way the screen cannot show — so the cost panel says "not
        // set" instead of inventing a provisional number.
        return "";
      default:
        return "";
    }
  }

  /** Override beats environment, environment beats the built-in default. */
  value(key: string): string {
    const o = this.overrides()[key];
    if (o) return o;
    const e = process.env[key];
    if (e) return e;
    return this.builtin(key);
  }

  source(key: string): SettingSource {
    if (this.overrides()[key]) return "screen";
    if (process.env[key]) return "env";
    return "default";
  }

  maxReplicas(): number {
    const n = Number.parseInt(this.value("MAX_REPLICAS"), 10);
    return Number.isFinite(n) && n > 0 ? n : 20;
  }

  /**
   * Applies a patch. Unknown keys are ignored rather than rejected: an old
   * client sending a retired key should not fail the whole save.
   */
  save(patch: Record<string, string>): void {
    const now = Date.now();
    for (const [k, v] of Object.entries(patch)) {
      if (!SPECS.some((spec) => spec.key === k)) continue;
      this.store?.saveSetting(k, String(v ?? "").trim(), now);
    }
  }

  /**
   * What the settings screen renders: every key with its value, where the value
   * came from, and what the environment alone would have produced — the last one
   * is what makes a screen override reversible.
   */
  view(): SettingsView {
    const rows: SettingRow[] = [];
    const envText: string[] = [];
    for (const spec of SPECS) {
      rows.push({
        ...spec,
        value: this.value(spec.key),
        source: this.source(spec.key),
        envValue: process.env[spec.key] ?? "",
        defaultValue: this.builtin(spec.key),
      });
      if (this.source(spec.key) === "screen") {
        envText.push(spec.key + "=" + this.value(spec.key));
      }
    }
    return { rows, envText: envText.join("\n") };
  }

  // --- typed getters --------------------------------------------------------
  // Getters, not frozen values: the settings screen writes overrides to SQLite
  // and they take effect on the next request.

  region(): string {
    return this.value("AWS_REGION");
  }
  wafWebAclName(): string {
    return this.value("WAF_WEB_ACL_NAME");
  }
  albName(): string {
    return this.value("ALB_NAME");
  }
  eksClusterName(): string {
    return this.value("EKS_CLUSTER_NAME");
  }
  rdsProxyName(): string {
    return this.value("RDS_PROXY_NAME");
  }
  wafLogGroup(): string {
    return this.value("WAF_LOG_GROUP");
  }
  appLogGroup(): string {
    return this.value("APP_LOG_GROUP");
  }
  targetNamespace(): string {
    return this.value("TARGET_NAMESPACE");
  }

  wafScope(): "CLOUDFRONT" | "REGIONAL" {
    return this.value("WAF_SCOPE") === "REGIONAL" ? "REGIONAL" : "CLOUDFRONT";
  }

  /** WAF metrics/API for CLOUDFRONT scope live in us-east-1 only. */
  wafRegion(): string {
    return this.wafScope() === "CLOUDFRONT" ? "us-east-1" : this.region();
  }
}
