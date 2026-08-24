package awsx

// ALB / EKS discovery, ported from aws.ts. The ALB and its target groups are
// created by the AWS Load Balancer Controller, so target-group names are
// auto-generated and must be discovered at runtime.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/cache"
)

type TargetGroupHandle struct {
	// CloudWatch dimension value, e.g. "targetgroup/k8s-default-user-abc/def"
	TgDim string
	Arn   string
	Name  string
	// Path pattern from the ALB listener rule routed to this TG, or "(default)".
	PathPattern string
}

type AlbDimensions struct {
	// e.g. "app/skills-alb/1234567890abcdef"
	LoadBalancer string
	TargetGroups []TargetGroupHandle
}

func (a *AWS) DiscoverAlb(ctx context.Context) (AlbDimensions, error) {
	return cache.Cached("aws:alb-dims", 5*time.Minute, func() (AlbDimensions, error) {
		return a.discoverAlb(ctx)
	}, 0)
}

func (a *AWS) discoverAlb(ctx context.Context) (AlbDimensions, error) {
	client, err := a.elbClient(ctx)
	if err != nil {
		return AlbDimensions{}, err
	}
	lbs, err := client.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{})
	if err != nil {
		return AlbDimensions{}, err
	}
	var lb *elbtypes.LoadBalancer
	albName := a.Settings.AlbName()
	for i := range lbs.LoadBalancers {
		if aws.ToString(lbs.LoadBalancers[i].LoadBalancerName) == albName {
			lb = &lbs.LoadBalancers[i]
			break
		}
	}
	if lb == nil {
		// Fall back only where there is nothing to get wrong. Taking the first
		// application load balancer out of several meant every
		// TargetResponseTime, every 5XX count and every target-group panel
		// downstream described a load balancer nobody named — and said nothing
		// about it, so the numbers looked healthy while belonging to something
		// else entirely. One ALB in the account is an unambiguous match; two is
		// a question only the operator can answer.
		candidates := []*elbtypes.LoadBalancer{}
		for i := range lbs.LoadBalancers {
			if lbs.LoadBalancers[i].Type == elbtypes.LoadBalancerTypeEnumApplication {
				candidates = append(candidates, &lbs.LoadBalancers[i])
			}
		}
		switch {
		case len(candidates) == 1:
			lb = candidates[0]
		case len(candidates) > 1:
			names := make([]string, 0, len(candidates))
			for _, c := range candidates {
				names = append(names, aws.ToString(c.LoadBalancerName))
			}
			return AlbDimensions{}, fmt.Errorf(
				"설정된 ALB 이름 %q 을(를) 찾지 못했고, 계정에 Application Load Balancer 가 %d개 있어 어느 것인지 결정할 수 없습니다: %s. "+
					"설정에서 ALB_NAME 을 지정하세요 — 임의로 하나를 고르면 엉뚱한 로드밸런서의 지연·상태 코드가 이 화면에 표시됩니다.",
				albName, len(candidates), strings.Join(names, ", "))
		}
	}
	if lb == nil || lb.LoadBalancerArn == nil {
		return AlbDimensions{}, fmt.Errorf(`ALB not found (looked for "%s")`, albName)
	}
	parts := strings.SplitN(*lb.LoadBalancerArn, ":loadbalancer/", 2)
	if len(parts) != 2 || parts[1] == "" {
		return AlbDimensions{}, fmt.Errorf("Unexpected ALB ARN format")
	}
	lbDim := parts[1]

	tgs, err := client.DescribeTargetGroups(ctx, &elbv2.DescribeTargetGroupsInput{LoadBalancerArn: lb.LoadBalancerArn})
	if err != nil {
		return AlbDimensions{}, err
	}

	pathByTgArn := map[string]string{}
	// listener/rule lookup is best-effort — TG metrics still work without path
	// labels.
	if listeners, err := client.DescribeListeners(ctx, &elbv2.DescribeListenersInput{LoadBalancerArn: lb.LoadBalancerArn}); err == nil {
		for _, listener := range listeners.Listeners {
			if listener.ListenerArn == nil {
				continue
			}
			ruleRes, err := client.DescribeRules(ctx, &elbv2.DescribeRulesInput{ListenerArn: listener.ListenerArn})
			if err != nil {
				continue
			}
			for _, rule := range ruleRes.Rules {
				pattern := "(unknown)"
				if aws.ToBool(rule.IsDefault) {
					pattern = "(default)"
				} else {
					for _, c := range rule.Conditions {
						if aws.ToString(c.Field) == "path-pattern" && c.PathPatternConfig != nil {
							pattern = strings.Join(c.PathPatternConfig.Values, ",")
						}
					}
				}
				for _, action := range rule.Actions {
					if action.Type == elbtypes.ActionTypeEnumForward && action.TargetGroupArn != nil {
						pathByTgArn[*action.TargetGroupArn] = pattern
					}
					if action.ForwardConfig != nil {
						for _, tg := range action.ForwardConfig.TargetGroups {
							if tg.TargetGroupArn != nil {
								pathByTgArn[*tg.TargetGroupArn] = pattern
							}
						}
					}
				}
			}
		}
	}

	targetGroups := []TargetGroupHandle{}
	for _, tg := range tgs.TargetGroups {
		if tg.TargetGroupArn == nil {
			continue
		}
		arnParts := strings.Split(*tg.TargetGroupArn, ":")
		if len(arnParts) < 6 {
			continue
		}
		tgDim := arnParts[5]
		name := aws.ToString(tg.TargetGroupName)
		if name == "" {
			name = tgDim
		}
		pattern, ok := pathByTgArn[*tg.TargetGroupArn]
		if !ok {
			pattern = "(unknown)"
		}
		targetGroups = append(targetGroups, TargetGroupHandle{
			TgDim: tgDim, Arn: *tg.TargetGroupArn, Name: name, PathPattern: pattern,
		})
	}
	return AlbDimensions{LoadBalancer: lbDim, TargetGroups: targetGroups}, nil
}

type NodeGroupScaling struct {
	Name        string
	MinSize     int
	MaxSize     int
	DesiredSize int
}

func (a *AWS) DiscoverNodeGroupScaling(ctx context.Context) ([]NodeGroupScaling, error) {
	return cache.Cached("aws:nodegroup-scaling", 5*time.Minute, func() ([]NodeGroupScaling, error) {
		client, err := a.eksClient(ctx)
		if err != nil {
			return nil, err
		}
		cluster := a.Settings.EksClusterName()
		list, err := client.ListNodegroups(ctx, &eks.ListNodegroupsInput{ClusterName: aws.String(cluster)})
		if err != nil {
			return nil, err
		}
		groups := []NodeGroupScaling{}
		for _, name := range list.Nodegroups {
			res, err := client.DescribeNodegroup(ctx, &eks.DescribeNodegroupInput{
				ClusterName: aws.String(cluster), NodegroupName: aws.String(name),
			})
			if err != nil {
				return nil, err
			}
			if res.Nodegroup != nil && res.Nodegroup.ScalingConfig != nil {
				sc := res.Nodegroup.ScalingConfig
				groups = append(groups, NodeGroupScaling{
					Name:        name,
					MinSize:     int(aws.ToInt32(sc.MinSize)),
					MaxSize:     int(aws.ToInt32(sc.MaxSize)),
					DesiredSize: int(aws.ToInt32(sc.DesiredSize)),
				})
			}
		}
		return groups, nil
	}, 0)
}
