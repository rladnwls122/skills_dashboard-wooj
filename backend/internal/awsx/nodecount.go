package awsx

// The two reads the node-count panel is built from, ported from nodecount.ts.
//
//   - describe-instances is the live number, and the same response answers the
//     off-spec question (type, region, unattached) without a second call.
//   - CloudTrail RunInstances/TerminateInstances reconstructs the stretches the
//     dashboard was not running for. It needs no prior setup, retains 90 days,
//     and — unlike the AutoScaling group metrics — does not miss Karpenter
//     nodes, which belong to no ASG at all.

import (
	"context"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	trailtypes "github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

func tagOf(inst ec2types.Instance, match func(string) bool) *string {
	for _, t := range inst.Tags {
		if t.Key != nil && match(*t.Key) {
			return types.Ptr(aws.ToString(t.Value))
		}
	}
	return nil
}

func ToInstanceRow(inst ec2types.Instance) types.InstanceRow {
	row := types.InstanceRow{
		ID:         aws.ToString(inst.InstanceId),
		Type:       string(inst.InstanceType),
		Name:       tagOf(inst, func(k string) bool { return k == "Name" }),
		ClusterTag: tagOf(inst, func(k string) bool { return strings.HasPrefix(k, "kubernetes.io/cluster/") }),
	}
	if inst.Placement != nil {
		row.AZ = aws.ToString(inst.Placement.AvailabilityZone)
	}
	if inst.LaunchTime != nil {
		row.LaunchedMs = types.Ptr(inst.LaunchTime.UnixMilli())
	}
	return row
}

// DescribeRunningInstances pages through the running instances. The state
// filter is server-side on purpose: without it every terminated instance from
// the last hour comes back and eats the page budget.
func (a *AWS) DescribeRunningInstances(ctx context.Context) ([]types.InstanceRow, error) {
	client, err := a.ec2Client(ctx)
	if err != nil {
		return nil, err
	}
	rows := []types.InstanceRow{}
	var token *string
	for {
		res, err := client.DescribeInstances(ctx, &ec2.DescribeInstancesInput{
			Filters:   []ec2types.Filter{{Name: aws.String("instance-state-name"), Values: []string{"running"}}},
			NextToken: token,
		})
		if err != nil {
			return nil, err
		}
		for _, r := range res.Reservations {
			for _, i := range r.Instances {
				rows = append(rows, ToInstanceRow(i))
			}
		}
		if res.NextToken == nil || *res.NextToken == "" {
			return rows, nil
		}
		token = res.NextToken
	}
}

// LookupInstanceEvents pages through one event name over one span.
//
// ponytail: called sequentially per event name, not in parallel. The API is
// capped at 2 TPS and the whole window is tens of events; parallelise only if
// the event count ever makes this slow.
func (a *AWS) LookupInstanceEvents(ctx context.Context, eventName string, fromMs, toMs int64) ([]types.CloudTrailEvent, error) {
	client, err := a.cloudTrailClient(ctx)
	if err != nil {
		return nil, err
	}
	out := []types.CloudTrailEvent{}
	var token *string
	for {
		res, err := client.LookupEvents(ctx, &cloudtrail.LookupEventsInput{
			LookupAttributes: []trailtypes.LookupAttribute{{
				AttributeKey:   trailtypes.LookupAttributeKeyEventName,
				AttributeValue: aws.String(eventName),
			}},
			StartTime: aws.Time(time.UnixMilli(fromMs)),
			EndTime:   aws.Time(time.UnixMilli(toMs)),
			NextToken: token,
		})
		if err != nil {
			return nil, err
		}
		for _, e := range res.Events {
			ev := types.CloudTrailEvent{
				Name: aws.ToString(e.EventName),
				Body: aws.ToString(e.CloudTrailEvent),
			}
			if e.EventTime != nil {
				ev.TsMs = e.EventTime.UnixMilli()
			}
			out = append(out, ev)
		}
		if res.NextToken == nil || *res.NextToken == "" {
			return out, nil
		}
		token = res.NextToken
	}
}
