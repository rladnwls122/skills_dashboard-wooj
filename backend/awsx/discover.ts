// Resource discovery for the settings screen.
//
// Every listing is bounded and every failure is reported rather than swallowed —
// a short list that says nothing about a denied call reads as "this account has
// none of these".

import { ListMetricsCommand } from "@aws-sdk/client-cloudwatch";
import { DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { ListClustersCommand } from "@aws-sdk/client-eks";
import { DescribeLoadBalancersCommand } from "@aws-sdk/client-elastic-load-balancing-v2";
import {
  GetLoggingConfigurationCommand,
  ListWebACLsCommand,
  type Scope,
} from "@aws-sdk/client-wafv2";

import type { DiscoveredResource, DiscoverKind, DiscoveryResult } from "../../src/lib/types.ts";
import { errMsg, type AWS } from "./clients.ts";

/**
 * One page of each listing. Discovery runs behind a button, so a bounded,
 * possibly incomplete list beats an unbounded walk.
 */
const PAGE_LIMIT = 100;

function mark(list: DiscoveredResource[], current: string): DiscoveredResource[] {
  for (const r of list) {
    if (r.id === current) r.current = true;
  }
  return list;
}

export function discover(a: AWS, kind: string): Promise<DiscoveryResult> {
  switch (kind) {
    case "webacl":
      return discoverWebAcls(a);
    case "waflog":
      return discoverWafLogGroups(a);
    case "alb":
      return discoverAlbs(a);
    case "eks":
      return discoverEksClusters(a);
    case "rdsproxy":
      return discoverRdsProxies(a);
    case "loggroup":
      return discoverAppLogGroups(a);
    default:
      return Promise.reject(new Error(`알 수 없는 탐색 종류: ${kind}`));
  }
}

async function discoverWebAcls(a: AWS): Promise<DiscoveryResult> {
  const resources: DiscoveredResource[] = [];
  const notes: string[] = [];
  // Both scopes are listed, not just the configured one: picking the WebACL is
  // usually how an operator discovers the scope is wrong.
  for (const scope of ["CLOUDFRONT", "REGIONAL"]) {
    const region = scope === "CLOUDFRONT" ? "us-east-1" : a.settings.region();
    try {
      const res = await a
        .wafClient(region)
        .send(new ListWebACLsCommand({ Scope: scope as Scope, Limit: PAGE_LIMIT }));
      for (const acl of res.WebACLs ?? []) {
        if (!acl.Name) continue;
        resources.push({ id: acl.Name, detail: `${scope} · ${region} · ${acl.Id ?? ""}` });
      }
    } catch (e) {
      // One denied scope must not hide the other. Saying so is the point.
      notes.push(`${scope} scope 조회 실패 (${region}): ${errMsg(e)}`);
    }
  }
  if (resources.length === 0 && notes.length === 0) {
    notes.push("두 scope 모두에서 WebACL 이 조회되지 않았습니다.");
  }
  return {
    kind: "webacl",
    resources: mark(resources, a.settings.wafWebAclName()),
    notes,
  };
}

const NOT_FOUND_RE = /nonexistent|not.*found/i;

async function discoverWafLogGroups(a: AWS): Promise<DiscoveryResult> {
  const resources: DiscoveredResource[] = [];
  const notes: string[] = [];

  // GetLoggingConfiguration says where THIS WebACL is actually logging — the
  // authoritative answer.
  try {
    const client = a.wafClient(a.settings.wafRegion());
    const acls = await client.send(
      new ListWebACLsCommand({ Scope: a.settings.wafScope() as Scope, Limit: PAGE_LIMIT }),
    );
    const arn = (acls.WebACLs ?? []).find((acl) => acl.Name === a.settings.wafWebAclName())?.ARN;
    if (!arn) {
      notes.push(
        `WebACL "${a.settings.wafWebAclName()}" 을(를) ${a.settings.wafScope()} scope(${a.settings.wafRegion()}) 에서 찾지 못했습니다 — 이름이나 scope 를 먼저 확인하세요.`,
      );
    } else {
      const cfg = await client.send(new GetLoggingConfigurationCommand({ ResourceArn: arn }));
      for (const dest of cfg.LoggingConfiguration?.LogDestinationConfigs ?? []) {
        // "arn:aws:logs:us-east-1:123:log-group:aws-waf-logs-x" — and some ARNs
        // carry a trailing ":*".
        const idx = dest.indexOf(":log-group:");
        if (idx >= 0) {
          const name = dest.slice(idx + ":log-group:".length).replace(/:\*$/, "");
          if (name !== "") {
            resources.push({ id: name, detail: "이 WebACL 에 이미 연결된 로깅 대상" });
          }
        } else if (dest.includes(":firehose:") || dest.includes(":s3:")) {
          notes.push(
            `이 WebACL 은 CloudWatch Logs 가 아닌 대상으로 로깅 중입니다 (${dest}) — 대시보드는 Logs Insights 만 읽으므로 사용할 수 없습니다.`,
          );
        }
      }
    }
  } catch (e) {
    // WAFNonexistentItemException is the normal "logging is off" answer.
    const msg = errMsg(e);
    if (NOT_FOUND_RE.test(msg)) {
      notes.push(
        "이 WebACL 에는 로깅이 설정되어 있지 않습니다 — 아래 후보 중 하나를 고르거나, WAF 콘솔에서 로깅을 켜세요.",
      );
    } else {
      notes.push("로깅 설정 조회 실패: " + msg);
    }
  }

  // Candidate destinations. WAF requires the group name to start with
  // "aws-waf-logs-", so anything else in the account cannot be one.
  try {
    const res = await a.logs(a.settings.wafRegion()).send(
      new DescribeLogGroupsCommand({ logGroupNamePrefix: "aws-waf-logs-", limit: 50 }),
    );
    for (const g of res.logGroups ?? []) {
      const name = g.logGroupName;
      if (!name || resources.some((r) => r.id === name)) continue;
      resources.push({ id: name, detail: `${a.settings.wafRegion()} · 연결 여부는 확인되지 않음` });
    }
  } catch (e) {
    notes.push(`로그 그룹 목록 조회 실패 (${a.settings.wafRegion()}): ${errMsg(e)}`);
  }

  if (resources.length === 0) {
    notes.push(
      'WAF 로그 그룹이 없습니다. WAF 콘솔에서 로깅을 켜면 됩니다 — 로그 그룹 이름은 반드시 "aws-waf-logs-" 로 시작해야 하고, CLOUDFRONT scope 면 us-east-1 에 있어야 합니다.',
    );
  }
  return { kind: "waflog", resources: mark(resources, a.settings.wafLogGroup()), notes };
}

async function discoverAlbs(a: AWS): Promise<DiscoveryResult> {
  const res = await a.elbClient().send(new DescribeLoadBalancersCommand({ PageSize: 50 }));
  const resources: DiscoveredResource[] = [];
  for (const l of res.LoadBalancers ?? []) {
    if (!l.LoadBalancerName) continue;
    resources.push({
      id: l.LoadBalancerName,
      detail: `${l.Type ?? ""} · ${l.State?.Code ?? ""} · ${l.DNSName ?? ""}`,
    });
  }
  return { kind: "alb", resources: mark(resources, a.settings.albName()), notes: [] };
}

async function discoverEksClusters(a: AWS): Promise<DiscoveryResult> {
  const res = await a.eksClient().send(new ListClustersCommand({ maxResults: PAGE_LIMIT }));
  const resources: DiscoveredResource[] = (res.clusters ?? []).map((c) => ({
    id: c,
    detail: a.settings.region(),
  }));
  return { kind: "eks", resources: mark(resources, a.settings.eksClusterName()), notes: [] };
}

/**
 * Takes proxy names from CloudWatch rather than the RDS API: the dashboard reads
 * proxy metrics and nothing else about the proxy, and this avoids an RDS SDK
 * client for a single listing.
 */
async function discoverRdsProxies(a: AWS): Promise<DiscoveryResult> {
  const res = await a
    .cloudWatch(a.settings.region())
    .send(new ListMetricsCommand({ Namespace: "AWS/RDS", MetricName: "ClientConnections" }));
  const names = new Set<string>();
  for (const m of res.Metrics ?? []) {
    for (const d of m.Dimensions ?? []) {
      if (d.Name === "ProxyName" && d.Value) names.add(d.Value);
    }
  }
  const resources: DiscoveredResource[] = [...names]
    .sort()
    .map((id) => ({ id, detail: "AWS/RDS ClientConnections 지표 보유" }));
  const notes =
    resources.length === 0
      ? [
          "AWS/RDS ClientConnections 지표를 가진 ProxyName 이 없습니다 — 프록시가 아직 지표를 게시하지 않았을 수 있습니다.",
        ]
      : [];
  return { kind: "rdsproxy", resources: mark(resources, a.settings.rdsProxyName()), notes };
}

async function discoverAppLogGroups(a: AWS): Promise<DiscoveryResult> {
  const client = a.logs(a.settings.region());
  const seen = new Map<string, string>();
  const notes: string[] = [];
  // ECS awslogs groups first (the 2025 task runs the binaries on ECS/EC2 —
  // one group per task definition is the usual layout), then the Container
  // Insights path, then anything under /aws/, because a cluster set up by
  // hand rarely uses the generated name.
  for (const prefix of ["/ecs/", "/aws/ecs/", "/aws/containerinsights/", "/aws/eks/", "/aws/"]) {
    try {
      const res = await client.send(
        new DescribeLogGroupsCommand({ logGroupNamePrefix: prefix, limit: 50 }),
      );
      for (const g of res.logGroups ?? []) {
        const name = g.logGroupName;
        if (!name || seen.has(name)) continue;
        seen.set(name, `${a.settings.region()} · ${g.storedBytes ?? 0} bytes`);
      }
    } catch (e) {
      notes.push(`${prefix} 조회 실패: ${errMsg(e)}`);
    }
    if (seen.size >= 50) break;
  }
  const resources: DiscoveredResource[] = [...seen].map(([id, detail]) => ({ id, detail }));
  return { kind: "loggroup", resources: mark(resources, a.settings.appLogGroup()), notes };
}

export type { DiscoverKind };
