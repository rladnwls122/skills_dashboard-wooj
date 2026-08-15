// Package awsx is the AWS-touching layer, ported from src/lib/server/aws.ts,
// cloudwatch.ts, logsinsights.ts, waf.ts, grading.ts and discover.ts. One
// instance holds every SDK client; the settings screen can change the region
// at runtime, so Reset throws the memoized clients away.
package awsx

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/creds"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/store"
)

type AWS struct {
	Settings *config.Settings
	Store    *store.Store
	// Credentials injected from the settings screen, or nil to sign with
	// whatever the SDK's own chain resolves (environment, ~/.aws, IRSA,
	// instance role).
	Creds *creds.Manager

	mu   sync.Mutex
	base *aws.Config
	// Every client captures a region at construction; keyed by region so WAF
	// (us-east-1 for CLOUDFRONT scope) and the workload region coexist.
	cw    map[string]*cloudwatch.Client
	cwl   map[string]*cloudwatchlogs.Client
	waf   map[string]*wafv2.Client
	elb   map[string]*elasticloadbalancingv2.Client
	eks   map[string]*eks.Client
	ec2   map[string]*ec2.Client
	trail map[string]*cloudtrail.Client
	sts   map[string]*sts.Client

	insightsSem chan struct{}
}

func New(settings *config.Settings, st *store.Store, cm *creds.Manager) *AWS {
	a := &AWS{
		Settings:    settings,
		Store:       st,
		Creds:       cm,
		insightsSem: make(chan struct{}, config.InsightsLimits.MaxConcurrent),
	}
	a.clearClients()
	return a
}

func (a *AWS) clearClients() {
	a.cw = map[string]*cloudwatch.Client{}
	a.cwl = map[string]*cloudwatchlogs.Client{}
	a.waf = map[string]*wafv2.Client{}
	a.elb = map[string]*elasticloadbalancingv2.Client{}
	a.eks = map[string]*eks.Client{}
	a.ec2 = map[string]*ec2.Client{}
	a.trail = map[string]*cloudtrail.Client{}
	a.sts = map[string]*sts.Client{}
}

// Reset drops the memoized clients and the config they were built from. A
// settings save changes which account and region every panel reads — a client
// built for the previous region keeps reporting "not found" for a resource that
// exists — and a credential injection changes which identity signs, which is
// captured in the base config.
func (a *AWS) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.base = nil
	a.clearClients()
}

func (a *AWS) baseConfig(ctx context.Context) (aws.Config, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.base != nil {
		return *a.base, nil
	}
	opts := []func(*awsconfig.LoadOptions) error{}
	if a.Creds != nil {
		if p := a.Creds.Provider(); p != nil {
			opts = append(opts, awsconfig.WithCredentialsProvider(p))
		}
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("AWS 자격증명 로드 실패: %w", err)
	}
	a.base = &cfg
	return cfg, nil
}

func clientFor[T any](a *AWS, ctx context.Context, cache map[string]*T, region string, build func(aws.Config, string) *T) (*T, error) {
	a.mu.Lock()
	if c, ok := cache[region]; ok {
		a.mu.Unlock()
		return c, nil
	}
	a.mu.Unlock()
	cfg, err := a.baseConfig(ctx)
	if err != nil {
		return nil, err
	}
	c := build(cfg, region)
	a.mu.Lock()
	cache[region] = c
	a.mu.Unlock()
	return c, nil
}

func (a *AWS) cloudWatch(ctx context.Context, region string) (*cloudwatch.Client, error) {
	return clientFor(a, ctx, a.cw, region, func(cfg aws.Config, r string) *cloudwatch.Client {
		return cloudwatch.NewFromConfig(cfg, func(o *cloudwatch.Options) { o.Region = r })
	})
}

func (a *AWS) logs(ctx context.Context, region string) (*cloudwatchlogs.Client, error) {
	return clientFor(a, ctx, a.cwl, region, func(cfg aws.Config, r string) *cloudwatchlogs.Client {
		return cloudwatchlogs.NewFromConfig(cfg, func(o *cloudwatchlogs.Options) { o.Region = r })
	})
}

func (a *AWS) wafClient(ctx context.Context, region string) (*wafv2.Client, error) {
	return clientFor(a, ctx, a.waf, region, func(cfg aws.Config, r string) *wafv2.Client {
		return wafv2.NewFromConfig(cfg, func(o *wafv2.Options) { o.Region = r })
	})
}

func (a *AWS) elbClient(ctx context.Context) (*elasticloadbalancingv2.Client, error) {
	return clientFor(a, ctx, a.elb, a.Settings.Region(), func(cfg aws.Config, r string) *elasticloadbalancingv2.Client {
		return elasticloadbalancingv2.NewFromConfig(cfg, func(o *elasticloadbalancingv2.Options) { o.Region = r })
	})
}

func (a *AWS) eksClient(ctx context.Context) (*eks.Client, error) {
	return clientFor(a, ctx, a.eks, a.Settings.Region(), func(cfg aws.Config, r string) *eks.Client {
		return eks.NewFromConfig(cfg, func(o *eks.Options) { o.Region = r })
	})
}

func (a *AWS) ec2Client(ctx context.Context) (*ec2.Client, error) {
	return clientFor(a, ctx, a.ec2, a.Settings.Region(), func(cfg aws.Config, r string) *ec2.Client {
		return ec2.NewFromConfig(cfg, func(o *ec2.Options) { o.Region = r })
	})
}

func (a *AWS) cloudTrailClient(ctx context.Context) (*cloudtrail.Client, error) {
	return clientFor(a, ctx, a.trail, a.Settings.Region(), func(cfg aws.Config, r string) *cloudtrail.Client {
		return cloudtrail.NewFromConfig(cfg, func(o *cloudtrail.Options) { o.Region = r })
	})
}

func (a *AWS) stsClient(ctx context.Context) (*sts.Client, error) {
	return clientFor(a, ctx, a.sts, a.Settings.Region(), func(cfg aws.Config, r string) *sts.Client {
		return sts.NewFromConfig(cfg, func(o *sts.Options) { o.Region = r })
	})
}

// ErrMsg mirrors the TS errMsg helper.
func ErrMsg(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}
