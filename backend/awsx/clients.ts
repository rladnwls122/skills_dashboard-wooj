// The AWS-touching layer. One instance holds every SDK client; the settings
// screen can change the region at runtime, so reset() throws the memoized
// clients away.

import { CloudTrailClient } from "@aws-sdk/client-cloudtrail";
import { CloudWatchClient } from "@aws-sdk/client-cloudwatch";
import { CloudWatchLogsClient } from "@aws-sdk/client-cloudwatch-logs";
import { EC2Client } from "@aws-sdk/client-ec2";
import { EKSClient } from "@aws-sdk/client-eks";
import { ElasticLoadBalancingV2Client } from "@aws-sdk/client-elastic-load-balancing-v2";
import { STSClient } from "@aws-sdk/client-sts";
import { WAFV2Client } from "@aws-sdk/client-wafv2";

import type { Settings } from "../config/config.ts";
import { INSIGHTS_LIMITS } from "../config/thresholds.ts";
import type { Manager } from "../creds/manager.ts";
import type { Store } from "../store/store.ts";

/** Bounds how many Insights queries run at once. */
export class Semaphore {
  private active = 0;
  private readonly waiting: (() => void)[] = [];
  // Written out rather than a constructor parameter property: the backend runs
  // through Node's type stripping, which erases types but does not synthesise
  // the assignment a parameter property implies.
  private readonly limit: number;

  constructor(limit: number) {
    this.limit = limit;
  }

  async run<T>(fn: () => Promise<T>): Promise<T> {
    // A loop, not a single check. Waking a waiter only schedules a microtask;
    // a fresh caller arriving before that continuation runs sees the freed slot
    // and takes it, and the woken waiter would then increment on top — putting
    // `active` over the limit and letting more Insights queries run at once
    // than the account tolerates. Re-checking after every wake is what makes
    // the bound real.
    while (this.active >= this.limit) {
      await new Promise<void>((resolve) => this.waiting.push(resolve));
    }
    this.active++;
    try {
      return await fn();
    } finally {
      this.active--;
      this.waiting.shift()?.();
    }
  }
}

type ClientCache<T> = Map<string, T>;

export class AWS {
  readonly settings: Settings;
  readonly store: Store | null;
  /**
   * Credentials injected from the settings screen, or null to sign with whatever
   * the SDK's own chain resolves (environment, ~/.aws, IRSA, instance role).
   */
  readonly creds: Manager | null;

  readonly insightsSem = new Semaphore(INSIGHTS_LIMITS.maxConcurrent);

  // Every client captures a region at construction; keyed by region so WAF
  // (us-east-1 for CLOUDFRONT scope) and the workload region coexist.
  private cw: ClientCache<CloudWatchClient> = new Map();
  private cwl: ClientCache<CloudWatchLogsClient> = new Map();
  private waf: ClientCache<WAFV2Client> = new Map();
  private elb: ClientCache<ElasticLoadBalancingV2Client> = new Map();
  private eks: ClientCache<EKSClient> = new Map();
  private ec2: ClientCache<EC2Client> = new Map();
  private trail: ClientCache<CloudTrailClient> = new Map();
  private sts: ClientCache<STSClient> = new Map();

  constructor(settings: Settings, store: Store | null, creds: Manager | null) {
    this.settings = settings;
    this.store = store;
    this.creds = creds;
  }

  /**
   * Drops the memoized clients. A settings save changes which account and region
   * every panel reads — a client built for the previous region keeps reporting
   * "not found" for a resource that exists — and a credential injection changes
   * which identity signs.
   */
  reset(): void {
    for (const cache of [this.cw, this.cwl, this.waf, this.elb, this.eks, this.ec2, this.trail, this.sts]) {
      for (const client of cache.values()) client.destroy();
      cache.clear();
    }
  }

  /**
   * The credentials every client is built with: the injected provider, or
   * undefined so the SDK resolves its own chain.
   */
  private credentials() {
    return this.creds?.provider();
  }

  private clientFor<T>(cache: ClientCache<T>, region: string, build: (region: string) => T): T {
    const hit = cache.get(region);
    if (hit) return hit;
    const made = build(region);
    cache.set(region, made);
    return made;
  }

  cloudWatch(region: string): CloudWatchClient {
    return this.clientFor(
      this.cw,
      region,
      (r) => new CloudWatchClient({ region: r, credentials: this.credentials() }),
    );
  }

  logs(region: string): CloudWatchLogsClient {
    return this.clientFor(
      this.cwl,
      region,
      (r) => new CloudWatchLogsClient({ region: r, credentials: this.credentials() }),
    );
  }

  wafClient(region: string): WAFV2Client {
    return this.clientFor(
      this.waf,
      region,
      (r) => new WAFV2Client({ region: r, credentials: this.credentials() }),
    );
  }

  elbClient(): ElasticLoadBalancingV2Client {
    return this.clientFor(
      this.elb,
      this.settings.region(),
      (r) => new ElasticLoadBalancingV2Client({ region: r, credentials: this.credentials() }),
    );
  }

  eksClient(): EKSClient {
    return this.clientFor(
      this.eks,
      this.settings.region(),
      (r) => new EKSClient({ region: r, credentials: this.credentials() }),
    );
  }

  ec2Client(): EC2Client {
    return this.clientFor(
      this.ec2,
      this.settings.region(),
      (r) => new EC2Client({ region: r, credentials: this.credentials() }),
    );
  }

  cloudTrailClient(): CloudTrailClient {
    return this.clientFor(
      this.trail,
      this.settings.region(),
      (r) => new CloudTrailClient({ region: r, credentials: this.credentials() }),
    );
  }

  stsClient(): STSClient {
    return this.clientFor(
      this.sts,
      this.settings.region(),
      (r) => new STSClient({ region: r, credentials: this.credentials() }),
    );
  }
}

/** The message an AWS failure carries, with the SDK noise trimmed off. */
export function errMsg(e: unknown): string {
  if (e === null || e === undefined) return "";
  if (e instanceof Error) return e.message;
  return String(e);
}

/** The AWS error code, when the SDK attached one. */
export function errCode(e: unknown): string {
  const named = e as { name?: string; Code?: string } | null;
  return named?.name ?? named?.Code ?? "";
}
