// ALB / EKS discovery. The ALB and its target groups are created by the AWS
// Load Balancer Controller, so target-group names are auto-generated and must be
// discovered at runtime.

import {
  DescribeListenersCommand,
  DescribeLoadBalancersCommand,
  DescribeRulesCommand,
  DescribeTargetGroupsCommand,
  type LoadBalancer,
} from "@aws-sdk/client-elastic-load-balancing-v2";
import { DescribeNodegroupCommand, ListNodegroupsCommand } from "@aws-sdk/client-eks";

import { cached } from "../cache/cache.ts";
import type { AWS } from "./clients.ts";

export interface TargetGroupHandle {
  /** CloudWatch dimension value, e.g. "targetgroup/k8s-default-user-abc/def" */
  tgDim: string;
  arn: string;
  name: string;
  /** Path pattern from the ALB listener rule routed to this TG, or "(default)". */
  pathPattern: string;
}

export interface AlbDimensions {
  /** e.g. "app/skills-alb/1234567890abcdef" */
  loadBalancer: string;
  targetGroups: TargetGroupHandle[];
}

export function discoverAlb(a: AWS): Promise<AlbDimensions> {
  return cached("aws:alb-dims", 5 * 60_000, () => discoverAlbUncached(a));
}

async function discoverAlbUncached(a: AWS): Promise<AlbDimensions> {
  const client = a.elbClient();
  const lbs = await client.send(new DescribeLoadBalancersCommand({}));
  const albName = a.settings.albName();
  const all = lbs.LoadBalancers ?? [];

  let lb: LoadBalancer | undefined = all.find((l) => l.LoadBalancerName === albName);
  // Substituting silently is worse than an empty panel: every TargetResponseTime
  // and status-code figure downstream would describe a load balancer nobody
  // named, and read as if it described the graded one. Only fall back when the
  // account leaves no ambiguity — exactly one ALB exists.
  if (!lb) {
    const apps = all.filter((l) => l.Type === "application");
    if (apps.length === 1) lb = apps[0];
    else if (apps.length > 1) {
      throw new Error(
        `ALB "${albName}" 을(를) 찾지 못했습니다. 계정에 ALB 가 ${apps.length}개 있어 임의로 고르지 않았습니다 ` +
          `(${apps.map((l) => l.LoadBalancerName).join(", ")}) — 설정에서 ALB_NAME 을 지정하세요.`,
      );
    }
  }
  if (!lb?.LoadBalancerArn) {
    throw new Error(`ALB not found (looked for "${albName}")`);
  }

  const [, lbDim] = lb.LoadBalancerArn.split(":loadbalancer/");
  if (!lbDim) throw new Error("Unexpected ALB ARN format");

  const tgs = await client.send(
    new DescribeTargetGroupsCommand({ LoadBalancerArn: lb.LoadBalancerArn }),
  );

  // The listener/rule lookup is best-effort — TG metrics still work without
  // path labels.
  const pathByTgArn = new Map<string, string>();
  try {
    const listeners = await client.send(
      new DescribeListenersCommand({ LoadBalancerArn: lb.LoadBalancerArn }),
    );
    for (const listener of listeners.Listeners ?? []) {
      if (!listener.ListenerArn) continue;
      let rules;
      try {
        rules = await client.send(
          new DescribeRulesCommand({ ListenerArn: listener.ListenerArn }),
        );
      } catch {
        continue;
      }
      for (const rule of rules.Rules ?? []) {
        let pattern = "(unknown)";
        if (rule.IsDefault) {
          pattern = "(default)";
        } else {
          for (const c of rule.Conditions ?? []) {
            if (c.Field === "path-pattern" && c.PathPatternConfig?.Values) {
              pattern = c.PathPatternConfig.Values.join(",");
            }
          }
        }
        for (const action of rule.Actions ?? []) {
          if (action.Type === "forward" && action.TargetGroupArn) {
            pathByTgArn.set(action.TargetGroupArn, pattern);
          }
          for (const tg of action.ForwardConfig?.TargetGroups ?? []) {
            if (tg.TargetGroupArn) pathByTgArn.set(tg.TargetGroupArn, pattern);
          }
        }
      }
    }
  } catch {
    // ignored — see above
  }

  const targetGroups: TargetGroupHandle[] = [];
  for (const tg of tgs.TargetGroups ?? []) {
    if (!tg.TargetGroupArn) continue;
    const arnParts = tg.TargetGroupArn.split(":");
    if (arnParts.length < 6) continue;
    const tgDimValue = arnParts[5]!;
    targetGroups.push({
      tgDim: tgDimValue,
      arn: tg.TargetGroupArn,
      name: tg.TargetGroupName || tgDimValue,
      pathPattern: pathByTgArn.get(tg.TargetGroupArn) ?? "(unknown)",
    });
  }

  return { loadBalancer: lbDim, targetGroups };
}

export interface NodeGroupScaling {
  name: string;
  minSize: number;
  maxSize: number;
  desiredSize: number;
}

export function discoverNodeGroupScaling(a: AWS): Promise<NodeGroupScaling[]> {
  return cached("aws:nodegroup-scaling", 5 * 60_000, async () => {
    const client = a.eksClient();
    const cluster = a.settings.eksClusterName();
    const list = await client.send(new ListNodegroupsCommand({ clusterName: cluster }));
    const groups: NodeGroupScaling[] = [];
    for (const name of list.nodegroups ?? []) {
      const res = await client.send(
        new DescribeNodegroupCommand({ clusterName: cluster, nodegroupName: name }),
      );
      const sc = res.nodegroup?.scalingConfig;
      if (sc) {
        groups.push({
          name,
          minSize: sc.minSize ?? 0,
          maxSize: sc.maxSize ?? 0,
          desiredSize: sc.desiredSize ?? 0,
        });
      }
    }
    return groups;
  });
}
