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
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/config"
	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/store"
)

type AWS struct {
	Settings *config.Settings
	Store    *store.Store

	mu   sync.Mutex
	base *aws.Config
	// Every client captures a region at construction; keyed by region so WAF
	// (us-east-1 for CLOUDFRONT scope) and the workload region coexist.
	cw  map[string]*cloudwatch.Client
	cwl map[string]*cloudwatchlogs.Client
	waf map[string]*wafv2.Client
	elb map[string]*elasticloadbalancingv2.Client
	eks map[string]*eks.Client

	insightsSem chan struct{}
}

func New(settings *config.Settings, st *store.Store) *AWS {
	return &AWS{
		Settings:    settings,
		Store:       st,
		cw:          map[string]*cloudwatch.Client{},
		cwl:         map[string]*cloudwatchlogs.Client{},
		waf:         map[string]*wafv2.Client{},
		elb:         map[string]*elasticloadbalancingv2.Client{},
		eks:         map[string]*eks.Client{},
		insightsSem: make(chan struct{}, config.InsightsLimits.MaxConcurrent),
	}
}

// Reset drops the memoized clients. A settings save changes which account and
// region every panel reads — a client built for the previous region keeps
// reporting "not found" for a resource that exists.
func (a *AWS) Reset() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.cw = map[string]*cloudwatch.Client{}
	a.cwl = map[string]*cloudwatchlogs.Client{}
	a.waf = map[string]*wafv2.Client{}
	a.elb = map[string]*elasticloadbalancingv2.Client{}
	a.eks = map[string]*eks.Client{}
}

func (a *AWS) baseConfig(ctx context.Context) (aws.Config, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.base != nil {
		return *a.base, nil
	}
	cfg, err := awsconfig.LoadDefaultConfig(ctx)
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

// ErrMsg mirrors the TS errMsg helper.
func ErrMsg(e error) string {
	if e == nil {
		return ""
	}
	return e.Error()
}
