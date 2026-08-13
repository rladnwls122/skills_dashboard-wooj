import "server-only";

// Where every environment value actually comes from, and how to change it
// without restarting.
//
// .env is read once at process start, so a wrong resource name meant editing a
// file and restarting — during a timed exercise that is the difference between
// fixing it and not. Overrides set on the 설정 screen live in SQLite and shadow
// .env, and `config.ts` reads through this module, so a save takes effect on
// the next request with no restart.
//
// Every value also carries where it came from. A dashboard that shows
// "skills-waf" without saying whether that is the operator's choice, the .env
// file, or a built-in default cannot be debugged when it points at the wrong
// account's resources.

import { loadSettings, saveSetting } from "./db";
import type { SettingSource, SettingSpec, SettingsView } from "@/lib/types";

export type SettingKey =
  | "AWS_REGION"
  | "WAF_SCOPE"
  | "WAF_WEB_ACL_NAME"
  | "WAF_LOG_GROUP"
  | "ALB_NAME"
  | "EKS_CLUSTER_NAME"
  | "RDS_PROXY_NAME"
  | "APP_LOG_GROUP"
  | "TARGET_NAMESPACE"
  | "MAX_REPLICAS"
  | "MATCH_START";

// The built-in fallback for each key, used when neither an override nor an
// .env value exists. Kept here rather than inline in config.ts so the settings
// screen can show the same default it would actually get.
function builtin(key: SettingKey): string {
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
      // Depends on the cluster name, which is itself overridable — so it is
      // resolved through `value()` rather than read from process.env directly.
      return `/aws/containerinsights/${value("EKS_CLUSTER_NAME")}/application`;
    case "TARGET_NAMESPACE":
      return "default";
    case "MAX_REPLICAS":
      return "20";
    case "MATCH_START":
      // Deliberately empty. The scoring window is derived from this value, and
      // a guessed start time produces a time-weighted average that is wrong in
      // a way the screen cannot show — so the cost panel says "not set" instead
      // of inventing a provisional number.
      return "";
  }
}

export const SETTING_SPECS: SettingSpec[] = [
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
    hint: "요청 로그·채점 지표 집계에 쓰는 CloudWatch Logs 그룹.",
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

// Overrides are read on every access rather than cached in a module variable:
// better-sqlite3 is synchronous, the table has ten rows, and a cache here would
// need invalidating from the save path in a way that is easy to get wrong. A
// setting that appears to save and then does not is the worst outcome.
function overrides(): Record<string, string> {
  try {
    return loadSettings();
  } catch {
    // A missing or locked database must not take the whole dashboard down —
    // .env still works.
    return {};
  }
}

function envValue(key: SettingKey): string {
  return process.env[key] ?? "";
}

// The value in force, with overrides beating .env and .env beating the built-in
// default.
export function value(key: SettingKey): string {
  const o = overrides()[key];
  if (o !== undefined && o !== "") return o;
  const e = envValue(key);
  if (e !== "") return e;
  return builtin(key);
}

export function sourceOf(key: SettingKey): SettingSource {
  const o = overrides()[key];
  if (o !== undefined && o !== "") return "screen";
  if (envValue(key) !== "") return "env";
  return "default";
}

export function saveSettings(patch: Record<string, string>): void {
  for (const [k, v] of Object.entries(patch)) {
    if (!SETTING_SPECS.some((s) => s.key === k)) continue;
    saveSetting(k, v.trim());
  }
}

// What the settings screen renders: every key with its current value, where it
// came from, and what .env alone would have produced. The last one is what
// makes "화면에서 바꾼 값" reversible — the operator can see what they are
// shadowing before they clear it.
export function settingsView(): SettingsView {
  return {
    rows: SETTING_SPECS.map((spec) => {
      const key = spec.key as SettingKey;
      return {
        ...spec,
        value: value(key),
        source: sourceOf(key),
        envValue: envValue(key),
        defaultValue: builtin(key),
      };
    }),
    // Pasteable into .env so a screen override survives a fresh checkout. The
    // screen is the fast path, not the permanent one.
    envText: SETTING_SPECS.filter((s) => sourceOf(s.key as SettingKey) === "screen")
      .map((s) => `${s.key}=${value(s.key as SettingKey)}`)
      .join("\n"),
  };
}
