package awsx

// Resource discovery for the settings screen, ported from discover.ts.
// Every listing is bounded and every failure is reported rather than
// swallowed — a short list that says nothing about a denied call reads as
// "this account has none of these".

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatch"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	elbv2 "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/wafv2"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

// One page of each listing. Discovery runs behind a button, so a bounded,
// possibly incomplete list beats an unbounded walk.
const pageLimit = 100

func mark(list []types.DiscoveredResource, current string) []types.DiscoveredResource {
	for i := range list {
		if list[i].ID == current {
			list[i].Current = types.Ptr(true)
		}
	}
	return list
}

func (a *AWS) Discover(ctx context.Context, kind string) (types.DiscoveryResult, error) {
	switch kind {
	case "webacl":
		return a.discoverWebAcls(ctx)
	case "waflog":
		return a.discoverWafLogGroups(ctx)
	case "alb":
		return a.discoverAlbs(ctx)
	case "eks":
		return a.discoverEksClusters(ctx)
	case "rdsproxy":
		return a.discoverRdsProxies(ctx)
	case "loggroup":
		return a.discoverAppLogGroups(ctx)
	default:
		return types.DiscoveryResult{}, fmt.Errorf("알 수 없는 탐색 종류: %s", kind)
	}
}

func (a *AWS) discoverWebAcls(ctx context.Context) (types.DiscoveryResult, error) {
	resources := []types.DiscoveredResource{}
	notes := []string{}
	// Both scopes are listed, not just the configured one: picking the WebACL
	// is usually how an operator discovers the scope is wrong.
	for _, scope := range []string{"CLOUDFRONT", "REGIONAL"} {
		region := a.Settings.Region()
		if scope == "CLOUDFRONT" {
			region = "us-east-1"
		}
		client, err := a.wafClient(ctx, region)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s scope 조회 실패 (%s): %s", scope, region, ErrMsg(err)))
			continue
		}
		res, err := client.ListWebACLs(ctx, &wafv2.ListWebACLsInput{
			Scope: waftypes.Scope(scope), Limit: aws.Int32(pageLimit),
		})
		if err != nil {
			// One denied scope must not hide the other. Saying so is the point.
			notes = append(notes, fmt.Sprintf("%s scope 조회 실패 (%s): %s", scope, region, ErrMsg(err)))
			continue
		}
		for _, acl := range res.WebACLs {
			if acl.Name == nil {
				continue
			}
			resources = append(resources, types.DiscoveredResource{
				ID:     *acl.Name,
				Detail: fmt.Sprintf("%s · %s · %s", scope, region, aws.ToString(acl.Id)),
			})
		}
	}
	if len(resources) == 0 && len(notes) == 0 {
		notes = append(notes, "두 scope 모두에서 WebACL 이 조회되지 않았습니다.")
	}
	return types.DiscoveryResult{Kind: "webacl", Resources: mark(resources, a.Settings.WafWebAclName()), Notes: notes}, nil
}

var notFoundRe = regexp.MustCompile(`(?i)nonexistent|not.*found`)

func (a *AWS) discoverWafLogGroups(ctx context.Context) (types.DiscoveryResult, error) {
	resources := []types.DiscoveredResource{}
	notes := []string{}

	// GetLoggingConfiguration says where THIS WebACL is actually logging — the
	// authoritative answer.
	if err := func() error {
		client, err := a.wafClient(ctx, a.Settings.WafRegion())
		if err != nil {
			return err
		}
		acls, err := client.ListWebACLs(ctx, &wafv2.ListWebACLsInput{
			Scope: waftypes.Scope(a.Settings.WafScope()), Limit: aws.Int32(pageLimit),
		})
		if err != nil {
			return err
		}
		var arn string
		for _, acl := range acls.WebACLs {
			if aws.ToString(acl.Name) == a.Settings.WafWebAclName() {
				arn = aws.ToString(acl.ARN)
				break
			}
		}
		if arn == "" {
			notes = append(notes, fmt.Sprintf(`WebACL "%s" 을(를) %s scope(%s) 에서 찾지 못했습니다 — 이름이나 scope 를 먼저 확인하세요.`,
				a.Settings.WafWebAclName(), a.Settings.WafScope(), a.Settings.WafRegion()))
			return nil
		}
		cfg, err := client.GetLoggingConfiguration(ctx, &wafv2.GetLoggingConfigurationInput{ResourceArn: aws.String(arn)})
		if err != nil {
			return err
		}
		if cfg.LoggingConfiguration != nil {
			for _, dest := range cfg.LoggingConfiguration.LogDestinationConfigs {
				// "arn:aws:logs:us-east-1:123:log-group:aws-waf-logs-x" — and
				// some ARNs carry a trailing ":*".
				parts := strings.SplitN(dest, ":log-group:", 2)
				if len(parts) == 2 {
					name := strings.TrimSuffix(parts[1], ":*")
					if name != "" {
						resources = append(resources, types.DiscoveredResource{ID: name, Detail: "이 WebACL 에 이미 연결된 로깅 대상"})
					}
				} else if strings.Contains(dest, ":firehose:") || strings.Contains(dest, ":s3:") {
					notes = append(notes, fmt.Sprintf("이 WebACL 은 CloudWatch Logs 가 아닌 대상으로 로깅 중입니다 (%s) — 대시보드는 Logs Insights 만 읽으므로 사용할 수 없습니다.", dest))
				}
			}
		}
		return nil
	}(); err != nil {
		// WAFNonexistentItemException is the normal "logging is off" answer.
		msg := ErrMsg(err)
		if notFoundRe.MatchString(msg) {
			notes = append(notes, "이 WebACL 에는 로깅이 설정되어 있지 않습니다 — 아래 후보 중 하나를 고르거나, WAF 콘솔에서 로깅을 켜세요.")
		} else {
			notes = append(notes, "로깅 설정 조회 실패: "+msg)
		}
	}

	// Candidate destinations. WAF requires the group name to start with
	// "aws-waf-logs-", so anything else in the account cannot be one.
	if client, err := a.logs(ctx, a.Settings.WafRegion()); err == nil {
		res, err := client.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
			LogGroupNamePrefix: aws.String("aws-waf-logs-"), Limit: aws.Int32(50),
		})
		if err != nil {
			notes = append(notes, fmt.Sprintf("로그 그룹 목록 조회 실패 (%s): %s", a.Settings.WafRegion(), ErrMsg(err)))
		} else {
			for _, g := range res.LogGroups {
				name := aws.ToString(g.LogGroupName)
				if name == "" {
					continue
				}
				dup := false
				for _, r := range resources {
					if r.ID == name {
						dup = true
						break
					}
				}
				if !dup {
					resources = append(resources, types.DiscoveredResource{
						ID: name, Detail: a.Settings.WafRegion() + " · 연결 여부는 확인되지 않음",
					})
				}
			}
		}
	} else {
		notes = append(notes, fmt.Sprintf("로그 그룹 목록 조회 실패 (%s): %s", a.Settings.WafRegion(), ErrMsg(err)))
	}

	if len(resources) == 0 {
		notes = append(notes, `WAF 로그 그룹이 없습니다. WAF 콘솔에서 로깅을 켜면 됩니다 — 로그 그룹 이름은 반드시 "aws-waf-logs-" 로 시작해야 하고, CLOUDFRONT scope 면 us-east-1 에 있어야 합니다.`)
	}
	return types.DiscoveryResult{Kind: "waflog", Resources: mark(resources, a.Settings.WafLogGroup()), Notes: notes}, nil
}

func (a *AWS) discoverAlbs(ctx context.Context) (types.DiscoveryResult, error) {
	client, err := a.elbClient(ctx)
	if err != nil {
		return types.DiscoveryResult{}, err
	}
	res, err := client.DescribeLoadBalancers(ctx, &elbv2.DescribeLoadBalancersInput{PageSize: aws.Int32(50)})
	if err != nil {
		return types.DiscoveryResult{}, err
	}
	resources := []types.DiscoveredResource{}
	for _, l := range res.LoadBalancers {
		if l.LoadBalancerName == nil {
			continue
		}
		state := ""
		if l.State != nil {
			state = string(l.State.Code)
		}
		resources = append(resources, types.DiscoveredResource{
			ID:     *l.LoadBalancerName,
			Detail: fmt.Sprintf("%s · %s · %s", l.Type, state, aws.ToString(l.DNSName)),
		})
	}
	return types.DiscoveryResult{Kind: "alb", Resources: mark(resources, a.Settings.AlbName()), Notes: []string{}}, nil
}

func (a *AWS) discoverEksClusters(ctx context.Context) (types.DiscoveryResult, error) {
	client, err := a.eksClient(ctx)
	if err != nil {
		return types.DiscoveryResult{}, err
	}
	res, err := client.ListClusters(ctx, &eks.ListClustersInput{MaxResults: aws.Int32(pageLimit)})
	if err != nil {
		return types.DiscoveryResult{}, err
	}
	resources := []types.DiscoveredResource{}
	for _, c := range res.Clusters {
		resources = append(resources, types.DiscoveredResource{ID: c, Detail: a.Settings.Region()})
	}
	return types.DiscoveryResult{Kind: "eks", Resources: mark(resources, a.Settings.EksClusterName()), Notes: []string{}}, nil
}

// discoverRdsProxies takes proxy names from CloudWatch rather than the RDS
// API: the dashboard reads proxy metrics and nothing else about the proxy, and
// this avoids an RDS SDK client for a single listing.
func (a *AWS) discoverRdsProxies(ctx context.Context) (types.DiscoveryResult, error) {
	client, err := a.cloudWatch(ctx, a.Settings.Region())
	if err != nil {
		return types.DiscoveryResult{}, err
	}
	res, err := client.ListMetrics(ctx, &cloudwatch.ListMetricsInput{
		Namespace: aws.String("AWS/RDS"), MetricName: aws.String("ClientConnections"),
	})
	if err != nil {
		return types.DiscoveryResult{}, err
	}
	names := map[string]struct{}{}
	for _, m := range res.Metrics {
		for _, d := range m.Dimensions {
			if aws.ToString(d.Name) == "ProxyName" && aws.ToString(d.Value) != "" {
				names[*d.Value] = struct{}{}
			}
		}
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	resources := []types.DiscoveredResource{}
	for _, n := range sorted {
		resources = append(resources, types.DiscoveredResource{ID: n, Detail: "AWS/RDS ClientConnections 지표 보유"})
	}
	notes := []string{}
	if len(resources) == 0 {
		notes = append(notes, "AWS/RDS ClientConnections 지표를 가진 ProxyName 이 없습니다 — 프록시가 아직 지표를 게시하지 않았을 수 있습니다.")
	}
	return types.DiscoveryResult{Kind: "rdsproxy", Resources: mark(resources, a.Settings.RdsProxyName()), Notes: notes}, nil
}

func (a *AWS) discoverAppLogGroups(ctx context.Context) (types.DiscoveryResult, error) {
	client, err := a.logs(ctx, a.Settings.Region())
	if err != nil {
		return types.DiscoveryResult{}, err
	}
	seen := map[string]string{}
	order := []string{}
	notes := []string{}
	// The Container Insights path first, then anything under /aws/, because a
	// cluster set up by hand rarely uses the generated name.
	for _, prefix := range []string{"/aws/containerinsights/", "/aws/eks/", "/aws/"} {
		res, err := client.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
			LogGroupNamePrefix: aws.String(prefix), Limit: aws.Int32(50),
		})
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s 조회 실패: %s", prefix, ErrMsg(err)))
		} else {
			for _, g := range res.LogGroups {
				name := aws.ToString(g.LogGroupName)
				if name == "" {
					continue
				}
				if _, ok := seen[name]; !ok {
					seen[name] = fmt.Sprintf("%s · %d bytes", a.Settings.Region(), aws.ToInt64(g.StoredBytes))
					order = append(order, name)
				}
			}
		}
		if len(seen) >= 50 {
			break
		}
	}
	resources := []types.DiscoveredResource{}
	for _, id := range order {
		resources = append(resources, types.DiscoveredResource{ID: id, Detail: seen[id]})
	}
	return types.DiscoveryResult{Kind: "loggroup", Resources: mark(resources, a.Settings.AppLogGroup()), Notes: notes}, nil
}
