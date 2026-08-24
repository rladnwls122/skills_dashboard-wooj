// The two reads the node-count panel is built from.
//
//   - describe-instances is the live number, and the same response answers the
//     off-spec question (type, region, unattached) without a second call.
//   - CloudTrail RunInstances/TerminateInstances reconstructs the stretches the
//     dashboard was not running for. It needs no prior setup, retains 90 days,
//     and — unlike the AutoScaling group metrics — does not miss Karpenter
//     nodes, which belong to no ASG at all.

import { LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import { DescribeInstancesCommand, type Instance } from "@aws-sdk/client-ec2";

import type { InstanceRow } from "../../src/lib/types.ts";
import type { CloudTrailEvent } from "../types/types.ts";
import type { AWS } from "./clients.ts";

function tagOf(inst: Instance, match: (key: string) => boolean): string | null {
  for (const t of inst.Tags ?? []) {
    if (t.Key && match(t.Key)) return t.Value ?? "";
  }
  return null;
}

export function toInstanceRow(inst: Instance): InstanceRow {
  return {
    id: inst.InstanceId ?? "",
    type: inst.InstanceType ?? "",
    name: tagOf(inst, (k) => k === "Name"),
    clusterTag: tagOf(inst, (k) => k.startsWith("kubernetes.io/cluster/")),
    az: inst.Placement?.AvailabilityZone ?? "",
    launchedMs: inst.LaunchTime ? new Date(inst.LaunchTime).getTime() : null,
  };
}

/**
 * Pages through the running instances. The state filter is server-side on
 * purpose: without it every terminated instance from the last hour comes back
 * and eats the page budget.
 */
export async function describeRunningInstances(a: AWS): Promise<InstanceRow[]> {
  const client = a.ec2Client();
  const rows: InstanceRow[] = [];
  let token: string | undefined;
  for (;;) {
    const res = await client.send(
      new DescribeInstancesCommand({
        Filters: [{ Name: "instance-state-name", Values: ["running"] }],
        NextToken: token,
      }),
    );
    for (const r of res.Reservations ?? []) {
      for (const i of r.Instances ?? []) rows.push(toInstanceRow(i));
    }
    if (!res.NextToken) return rows;
    token = res.NextToken;
  }
}

/**
 * Pages through one event name over one span.
 *
 * Called sequentially per event name, not in parallel: the API is capped at
 * 2 TPS and the whole window is tens of events.
 */
export async function lookupInstanceEvents(
  a: AWS,
  eventName: string,
  fromMs: number,
  toMs: number,
): Promise<CloudTrailEvent[]> {
  const client = a.cloudTrailClient();
  const out: CloudTrailEvent[] = [];
  let token: string | undefined;
  for (;;) {
    const res = await client.send(
      new LookupEventsCommand({
        LookupAttributes: [{ AttributeKey: "EventName", AttributeValue: eventName }],
        StartTime: new Date(fromMs),
        EndTime: new Date(toMs),
        NextToken: token,
      }),
    );
    for (const e of res.Events ?? []) {
      out.push({
        name: e.EventName ?? "",
        body: e.CloudTrailEvent ?? "",
        tsMs: e.EventTime ? new Date(e.EventTime).getTime() : 0,
      });
    }
    if (!res.NextToken) return out;
    token = res.NextToken;
  }
}
