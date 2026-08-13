import "server-only";
import { CloudWatchClient } from "@aws-sdk/client-cloudwatch";
import { CloudWatchLogsClient } from "@aws-sdk/client-cloudwatch-logs";
import { DescribeNodegroupCommand, EKSClient, ListNodegroupsCommand } from "@aws-sdk/client-eks";
import {
  DescribeListenersCommand,
  DescribeLoadBalancersCommand,
  DescribeRulesCommand,
  DescribeTargetGroupsCommand,
  ElasticLoadBalancingV2Client,
} from "@aws-sdk/client-elastic-load-balancing-v2";
import { WAFV2Client } from "@aws-sdk/client-wafv2";
import { CloudTrailClient } from "@aws-sdk/client-cloudtrail";
import { EC2Client } from "@aws-sdk/client-ec2";
import { cached } from "./cache";
import { ENV, wafRegion } from "./config";

let cw: CloudWatchClient | null = null;
let cwWaf: CloudWatchClient | null = null;
let waf: WAFV2Client | null = null;
let elb: ElasticLoadBalancingV2Client | null = null;
let cwl: CloudWatchLogsClient | null = null;
let eks: EKSClient | null = null;
let cwlRegional: CloudWatchLogsClient | null = null;
let ec2: EC2Client | null = null;
let trail: CloudTrailClient | null = null;
const cwlByRegion = new Map<string, CloudWatchLogsClient>();

// Every client above is built once and reused. They capture a region at
// construction, and the region is now settable at runtime, so a settings save
// has to throw them away — otherwise the dashboard keeps talking to the
// previous account's region and reports "not found" for a resource that exists.
export function resetAwsClients(): void {
  cw = null;
  cwWaf = null;
  waf = null;
  elb = null;
  cwl = null;
  cwlRegional = null;
  eks = null;
  ec2 = null;
  trail = null;
  cwlByRegion.clear();
}

export function cloudWatch(): CloudWatchClient {
  if (!cw) cw = new CloudWatchClient({ region: ENV.region });
  return cw;
}

// WAF metrics for CLOUDFRONT-scope ACLs are only published in us-east-1.
export function cloudWatchForWaf(): CloudWatchClient {
  if (!cwWaf) cwWaf = new CloudWatchClient({ region: wafRegion() });
  return cwWaf;
}

export function wafClient(): WAFV2Client {
  if (!waf) waf = new WAFV2Client({ region: wafRegion() });
  return waf;
}

export function elbClient(): ElasticLoadBalancingV2Client {
  if (!elb) elb = new ElasticLoadBalancingV2Client({ region: ENV.region });
  return elb;
}

export function logsClient(): CloudWatchLogsClient {
  if (!cwl) cwl = new CloudWatchLogsClient({ region: wafRegion() });
  return cwl;
}

// Container Insights application logs live in the cluster region, unlike the
// CLOUDFRONT-scope WAF logs which are us-east-1 only.
export function logsClientRegional(): CloudWatchLogsClient {
  if (!cwlRegional) cwlRegional = new CloudWatchLogsClient({ region: ENV.region });
  return cwlRegional;
}

// A Logs client for a named region. WAF logs and application logs can live in
// different regions at the same time, so one memoised client per region rather
// than one for "the" region.
export function logsClientFor(region: string): CloudWatchLogsClient {
  let c = cwlByRegion.get(region);
  if (!c) {
    c = new CloudWatchLogsClient({ region });
    cwlByRegion.set(region, c);
  }
  return c;
}

export function eksClient(): EKSClient {
  if (!eks) eks = new EKSClient({ region: ENV.region });
  return eks;
}

export function ec2Client(): EC2Client {
  if (!ec2) ec2 = new EC2Client({ region: ENV.region });
  return ec2;
}

// CloudTrail is read in the cluster region: RunInstances/TerminateInstances are
// regional events, and the scored instances only ever run in the region the
// task assigns.
export function cloudTrailClient(): CloudTrailClient {
  if (!trail) trail = new CloudTrailClient({ region: ENV.region });
  return trail;
}

export interface TargetGroupHandle {
  // CloudWatch dimension value, e.g. "targetgroup/k8s-default-user-abc/def"
  tgDim: string;
  arn: string;
  name: string;
  // Path pattern from the ALB listener rule routed to this TG (e.g. "/v1/user*"),
  // or "(default)" when it's the listener's default action.
  pathPattern: string;
}

export interface AlbDimensions {
  // e.g. "app/skills-alb/1234567890abcdef"
  loadBalancer: string;
  targetGroups: TargetGroupHandle[];
}

// The ALB and its target groups are created by the AWS Load Balancer Controller,
// so target-group names are auto-generated and must be discovered at runtime.
// Path patterns come from the listener rules (spec-defined /v1/user, /v1/product,
// /v1/stress in this environment) rather than the generated TG name.
export async function discoverAlb(): Promise<AlbDimensions> {
  return cached("aws:alb-dims", 5 * 60_000, async () => {
    const client = elbClient();
    const lbs = await client.send(new DescribeLoadBalancersCommand({}));
    const lb =
      lbs.LoadBalancers?.find((l) => l.LoadBalancerName === ENV.albName) ??
      lbs.LoadBalancers?.find((l) => l.Type === "application");
    if (!lb?.LoadBalancerArn) {
      throw new Error(`ALB not found (looked for "${ENV.albName}")`);
    }
    const lbDim = lb.LoadBalancerArn.split(":loadbalancer/")[1];
    if (!lbDim) throw new Error("Unexpected ALB ARN format");

    const tgs = await client.send(
      new DescribeTargetGroupsCommand({ LoadBalancerArn: lb.LoadBalancerArn }),
    );
    const pathByTgArn = new Map<string, string>();
    try {
      const listeners = await client.send(
        new DescribeListenersCommand({ LoadBalancerArn: lb.LoadBalancerArn }),
      );
      for (const listener of listeners.Listeners ?? []) {
        if (!listener.ListenerArn) continue;
        const rules = await client.send(
          new DescribeRulesCommand({ ListenerArn: listener.ListenerArn }),
        );
        for (const rule of rules.Rules ?? []) {
          const pathCondition = rule.Conditions?.find((c) => c.Field === "path-pattern");
          const pattern = rule.IsDefault
            ? "(default)"
            : (pathCondition?.PathPatternConfig?.Values?.join(",") ?? "(unknown)");
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
      // listener/rule lookup is best-effort — TG metrics still work without path labels
    }

    const targetGroups: TargetGroupHandle[] = (tgs.TargetGroups ?? [])
      .map((tg): TargetGroupHandle | null => {
        if (!tg.TargetGroupArn) return null;
        const tgDim = tg.TargetGroupArn.split(":").at(5);
        if (!tgDim) return null;
        return {
          tgDim,
          arn: tg.TargetGroupArn,
          name: tg.TargetGroupName ?? tgDim,
          pathPattern: pathByTgArn.get(tg.TargetGroupArn) ?? "(unknown)",
        };
      })
      .filter((t): t is TargetGroupHandle => t !== null);
    return { loadBalancer: lbDim, targetGroups };
  });
}

export interface NodeGroupScaling {
  name: string;
  minSize: number;
  maxSize: number;
  desiredSize: number;
}

export async function discoverNodeGroupScaling(): Promise<NodeGroupScaling[]> {
  return cached("aws:nodegroup-scaling", 5 * 60_000, async () => {
    const client = eksClient();
    const list = await client.send(
      new ListNodegroupsCommand({ clusterName: ENV.eksClusterName }),
    );
    const names = list.nodegroups ?? [];
    const groups: NodeGroupScaling[] = [];
    for (const name of names) {
      const res = await client.send(
        new DescribeNodegroupCommand({ clusterName: ENV.eksClusterName, nodegroupName: name }),
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
