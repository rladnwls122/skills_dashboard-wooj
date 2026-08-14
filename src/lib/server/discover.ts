import "server-only";

// Finds the AWS resources the settings screen asks about.
//
// The names in .env are guesses until something confirms them, and a wrong one
// fails silently: the panel is empty, the metric has no data, the WebACL is
// "not found". Rather than asking the operator to type a name correctly, this
// lists what the account actually has and lets them pick.
//
// Every listing is bounded and every failure is reported rather than swallowed.
// A short list that says nothing about a denied call reads as "this account has
// none of these", which is the most expensive wrong answer here.

import { ListMetricsCommand } from "@aws-sdk/client-cloudwatch";
import { DescribeLogGroupsCommand } from "@aws-sdk/client-cloudwatch-logs";
import { ListClustersCommand } from "@aws-sdk/client-eks";
import { DescribeLoadBalancersCommand } from "@aws-sdk/client-elastic-load-balancing-v2";
import { GetLoggingConfigurationCommand, ListWebACLsCommand } from "@aws-sdk/client-wafv2";
import {
  cloudWatch,
  eksClient,
  elbClient,
  logsClient,
  logsClientRegional,
  wafClient,
  wafClientFor,
} from "./aws";
import { errMsg } from "./cloudwatch";
import { ENV, wafRegion } from "./config";
import type { DiscoverKind, DiscoveredResource, DiscoveryResult } from "@/lib/types";

// One page of each listing. Discovery runs behind a button, so a bounded,
// possibly incomplete list beats an unbounded walk that holds the request open.
const PAGE_LIMIT = 100;

function mark(list: DiscoveredResource[], current: string): DiscoveredResource[] {
  return list.map((r) => (r.id === current ? { ...r, current: true } : r));
}

async function webAcls(): Promise<DiscoveryResult> {
  const resources: DiscoveredResource[] = [];
  const notes: string[] = [];
  // Both scopes are listed, not just the configured one: picking the WebACL is
  // usually how an operator discovers the scope is wrong in the first place.
  for (const scope of ["CLOUDFRONT", "REGIONAL"] as const) {
    const region = scope === "CLOUDFRONT" ? "us-east-1" : ENV.region;
    try {
      const client = wafClientFor(region);
      const res = await client.send(new ListWebACLsCommand({ Scope: scope, Limit: PAGE_LIMIT }));
      for (const acl of res.WebACLs ?? []) {
        if (!acl.Name) continue;
        resources.push({ id: acl.Name, detail: `${scope} · ${region} · ${acl.Id ?? ""}` });
      }
    } catch (e) {
      // One denied scope must not hide the other. Saying so is the whole point.
      notes.push(`${scope} scope 조회 실패 (${region}): ${errMsg(e)}`);
    }
  }
  if (resources.length === 0 && notes.length === 0) {
    notes.push("두 scope 모두에서 WebACL 이 조회되지 않았습니다.");
  }
  return { kind: "webacl", resources: mark(resources, ENV.wafWebAclName), notes };
}

// The WAF log group.
//
// Two ways to find it, tried in order, because they answer slightly different
// questions. GetLoggingConfiguration says where THIS WebACL is actually logging
// — the authoritative answer. Listing `aws-waf-logs-*` groups finds destinations
// that exist but are not wired up, which is the more common half-finished state
// and worth offering rather than reporting nothing.
async function wafLogGroups(): Promise<DiscoveryResult> {
  const resources: DiscoveredResource[] = [];
  const notes: string[] = [];

  try {
    const acls = await wafClient().send(
      new ListWebACLsCommand({ Scope: ENV.wafScope, Limit: PAGE_LIMIT }),
    );
    const acl = acls.WebACLs?.find((a) => a.Name === ENV.wafWebAclName);
    if (!acl?.ARN) {
      notes.push(
        `WebACL "${ENV.wafWebAclName}" 을(를) ${ENV.wafScope} scope(${wafRegion()}) 에서 찾지 못했습니다 — 이름이나 scope 를 먼저 확인하세요.`,
      );
    } else {
      const cfg = await wafClient().send(
        new GetLoggingConfigurationCommand({ ResourceArn: acl.ARN }),
      );
      for (const dest of cfg.LoggingConfiguration?.LogDestinationConfigs ?? []) {
        // "arn:aws:logs:us-east-1:123:log-group:aws-waf-logs-x" — and some
        // ARNs carry a trailing ":*".
        const name = dest.split(":log-group:")[1]?.replace(/:\*$/, "");
        if (name) {
          resources.push({ id: name, detail: "이 WebACL 에 이미 연결된 로깅 대상" });
        } else if (dest.includes(":firehose:") || dest.includes(":s3:")) {
          notes.push(
            `이 WebACL 은 CloudWatch Logs 가 아닌 대상으로 로깅 중입니다 (${dest}) — 대시보드는 Logs Insights 만 읽으므로 사용할 수 없습니다.`,
          );
        }
      }
    }
  } catch (e) {
    // WAFNonexistentItemException is the normal "logging is off" answer, not a
    // failure worth alarming about.
    const msg = errMsg(e);
    notes.push(
      /nonexistent|not.*found/i.test(msg)
        ? "이 WebACL 에는 로깅이 설정되어 있지 않습니다 — 아래 후보 중 하나를 고르거나, WAF 콘솔에서 로깅을 켜세요."
        : `로깅 설정 조회 실패: ${msg}`,
    );
  }

  // Candidate destinations. WAF requires the group name to start with
  // "aws-waf-logs-", so anything else in the account cannot be one.
  try {
    const res = await logsClient().send(
      new DescribeLogGroupsCommand({ logGroupNamePrefix: "aws-waf-logs-", limit: 50 }),
    );
    for (const g of res.logGroups ?? []) {
      if (!g.logGroupName || resources.some((r) => r.id === g.logGroupName)) continue;
      resources.push({
        id: g.logGroupName,
        detail: `${wafRegion()} · 연결 여부는 확인되지 않음`,
      });
    }
  } catch (e) {
    notes.push(`로그 그룹 목록 조회 실패 (${wafRegion()}): ${errMsg(e)}`);
  }

  if (resources.length === 0) {
    notes.push(
      'WAF 로그 그룹이 없습니다. WAF 콘솔에서 로깅을 켜면 됩니다 — 로그 그룹 이름은 반드시 "aws-waf-logs-" 로 시작해야 하고, CLOUDFRONT scope 면 us-east-1 에 있어야 합니다.',
    );
  }
  return { kind: "waflog", resources: mark(resources, ENV.wafLogGroup), notes };
}

async function albs(): Promise<DiscoveryResult> {
  const res = await elbClient().send(new DescribeLoadBalancersCommand({ PageSize: 50 }));
  const resources = (res.LoadBalancers ?? [])
    .filter((l) => l.LoadBalancerName)
    .map((l) => ({
      id: l.LoadBalancerName!,
      detail: `${l.Type ?? ""} · ${l.State?.Code ?? ""} · ${l.DNSName ?? ""}`,
    }));
  return { kind: "alb", resources: mark(resources, ENV.albName), notes: [] };
}

async function eksClusters(): Promise<DiscoveryResult> {
  const res = await eksClient().send(new ListClustersCommand({ maxResults: PAGE_LIMIT }));
  const resources = (res.clusters ?? []).map((c) => ({ id: c, detail: ENV.region }));
  return { kind: "eks", resources: mark(resources, ENV.eksClusterName), notes: [] };
}

// RDS Proxy names, taken from CloudWatch rather than the RDS API.
//
// The dashboard reads proxy metrics and nothing else about the proxy, so the
// name it needs is the one CloudWatch publishes under. Asking CloudWatch also
// avoids adding an RDS SDK client for a single listing — and a proxy that
// exists but publishes no metrics would be a name the dashboard could not use
// anyway.
async function rdsProxies(): Promise<DiscoveryResult> {
  const res = await cloudWatch().send(
    new ListMetricsCommand({ Namespace: "AWS/RDS", MetricName: "ClientConnections" }),
  );
  const names = new Set<string>();
  for (const m of res.Metrics ?? []) {
    const dim = m.Dimensions?.find((d) => d.Name === "ProxyName");
    if (dim?.Value) names.add(dim.Value);
  }
  const resources = [...names].sort().map((n) => ({ id: n, detail: "AWS/RDS ClientConnections 지표 보유" }));
  return {
    kind: "rdsproxy",
    resources: mark(resources, ENV.rdsProxyName),
    notes:
      resources.length === 0
        ? ["AWS/RDS ClientConnections 지표를 가진 ProxyName 이 없습니다 — 프록시가 아직 지표를 게시하지 않았을 수 있습니다."]
        : [],
  };
}

async function appLogGroups(): Promise<DiscoveryResult> {
  const client = logsClientRegional();
  const seen = new Map<string, string>();
  const notes: string[] = [];
  // The Container Insights path first, then anything containing "application",
  // because a cluster set up by hand rarely uses the generated name.
  for (const prefix of [`/aws/containerinsights/`, "/aws/eks/", "/aws/"]) {
    try {
      const res = await client.send(
        new DescribeLogGroupsCommand({ logGroupNamePrefix: prefix, limit: 50 }),
      );
      for (const g of res.logGroups ?? []) {
        if (g.logGroupName) seen.set(g.logGroupName, `${ENV.region} · ${g.storedBytes ?? 0} bytes`);
      }
    } catch (e) {
      notes.push(`${prefix} 조회 실패: ${errMsg(e)}`);
    }
    if (seen.size >= 50) break;
  }
  const resources = [...seen].map(([id, detail]) => ({ id, detail }));
  return { kind: "loggroup", resources: mark(resources, ENV.appLogGroup), notes };
}

export async function discover(kind: DiscoverKind): Promise<DiscoveryResult> {
  switch (kind) {
    case "webacl":
      return webAcls();
    case "waflog":
      return wafLogGroups();
    case "alb":
      return albs();
    case "eks":
      return eksClusters();
    case "rdsproxy":
      return rdsProxies();
    case "loggroup":
      return appLogGroups();
  }
}
