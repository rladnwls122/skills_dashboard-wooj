// Package nodecost is the arithmetic behind the node-count panel — the one
// grader input this dashboard can count itself.
//
// The cost score is computed from how many instances were running during the
// scoring window (match start +1h to +3h), sampled every few minutes. The
// formula from count to score is sealed, so this package produces counts and
// never a score.
//
// Everything here is pure: the AWS reads live in awsx, the samples come from
// SQLite, and this is the part that can be reasoned about without either.
// Ported from nodecount.ts.
package nodecost

import (
	"os"
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

const (
	// The scoring window opens an hour after the match starts and runs for two.
	WindowOffset = time.Hour
	WindowLength = 2 * time.Hour
	// The only instance type the 2025 task sheet allows for workload hosts
	// ("EC2 인스턴스는 c5.large 타입만"). Overridable with ALLOWED_INSTANCE_TYPE
	// for a variant of the task that names another type.
	DefaultAllowedType = "c5.large"
	// Readings are floored to a 30s grid, matching the poll interval. The
	// primary key is (key, t), so the floor makes repeated writes inside one
	// bucket idempotent instead of accumulating rows.
	GridMs = 30_000
	// The metric_samples key the readings are stored under.
	SampleKey = "nodes:count"
)

type Sample struct {
	T int64
	V float64
}

// --- match start and the window it implies -----------------------------------

var (
	hhmmRe = regexp.MustCompile(`^(\d{1,2}):(\d{2})$`)
	fullRe = regexp.MustCompile(`^(\d{4})-(\d{2})-(\d{2})[T ](\d{1,2}):(\d{2})`)
)

// ParseMatchStart accepts what a person types under time pressure:
// "2026-08-14 09:00", "2026-08-14T09:00", or a bare "09:00" meaning today.
// Interpreted in the machine's local time, which is the clock the operator is
// reading.
func ParseMatchStart(raw string, nowMs int64) (int64, bool) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return 0, false
	}
	if m := hhmmRe.FindStringSubmatch(s); m != nil {
		h, _ := strconv.Atoi(m[1])
		min, _ := strconv.Atoi(m[2])
		now := time.UnixMilli(nowMs)
		d := time.Date(now.Year(), now.Month(), now.Day(), h, min, 0, 0, now.Location())
		return d.UnixMilli(), true
	}
	if m := fullRe.FindStringSubmatch(s); m != nil {
		y, _ := strconv.Atoi(m[1])
		mo, _ := strconv.Atoi(m[2])
		day, _ := strconv.Atoi(m[3])
		h, _ := strconv.Atoi(m[4])
		min, _ := strconv.Atoi(m[5])
		d := time.Date(y, time.Month(mo), day, h, min, 0, 0, time.Local)
		return d.UnixMilli(), true
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UnixMilli(), true
		}
	}
	return 0, false
}

func Window(startMs int64) types.ScoringWindow {
	return types.ScoringWindow{
		StartMs: startMs + WindowOffset.Milliseconds(),
		EndMs:   startMs + WindowOffset.Milliseconds() + WindowLength.Milliseconds(),
	}
}

// --- the arithmetic ----------------------------------------------------------

// TimeWeightedAvg is the mean of a step function. Samples are readings, not
// events: a value holds until the next one replaces it, so a five-minute
// stretch at 6 nodes weighs five times a one-minute stretch at 6.
//
// A plain mean of the samples would be wrong whenever the poll interval is
// uneven — which it is, because the dashboard gets closed and reopened.
func TimeWeightedAvg(samples []Sample, fromMs, toMs int64) *float64 {
	if toMs <= fromMs {
		return nil
	}
	sorted := append([]Sample(nil), samples...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].T < sorted[j].T })

	// The value in effect when the window opens is the last reading at or
	// before it, not the first reading inside it.
	var cur *float64
	inside := []Sample{}
	for _, s := range sorted {
		switch {
		case s.T <= fromMs:
			v := s.V
			cur = &v
		case s.T < toMs:
			inside = append(inside, s)
		}
	}
	if cur == nil {
		if len(inside) == 0 {
			return nil
		}
		// Nothing was recorded before the window opened. Holding the first
		// reading backwards is the only assumption available; backfill normally
		// makes this branch unreachable.
		v := inside[0].V
		cur = &v
	}

	area := 0.0
	prevT := fromMs
	for _, s := range inside {
		area += *cur * float64(s.T-prevT)
		v := s.V
		cur = &v
		prevT = s.T
	}
	area += *cur * float64(toMs-prevT)
	out := area / float64(toMs-fromMs)
	return &out
}

// Projection is the part of the panel that is arithmetic rather than a reading.
type Projection struct {
	Current             *int
	ElapsedMin          *int
	RemainingMin        *int
	CumulativeAvg       *float64
	FinalAvg            *float64
	MarginalPerInstance *float64
}

// Project is what the window average lands on if the current count is held to
// the end, and how much one instance moves it.
//
//	final    = (cumulative × elapsed + current × remaining) / W
//	marginal = remaining / W
//
// The marginal term is the number the scaling decision actually turns on: the
// same instance costs less the later it is added, and near the end of the
// window it costs almost nothing.
func Project(samples []Sample, current *int, win types.ScoringWindow, nowMs int64) Projection {
	w := win.EndMs - win.StartMs
	clampedNow := nowMs
	if clampedNow < win.StartMs {
		clampedNow = win.StartMs
	}
	if clampedNow > win.EndMs {
		clampedNow = win.EndMs
	}
	elapsed := clampedNow - win.StartMs
	remaining := w - elapsed

	var cumulative *float64
	if elapsed > 0 {
		cumulative = TimeWeightedAvg(samples, win.StartMs, clampedNow)
	}
	base := cumulative
	if base == nil && current != nil {
		base = types.Ptr(float64(*current))
	}

	out := Projection{
		Current:             current,
		ElapsedMin:          types.Ptr(int(math.Round(float64(elapsed) / 60_000))),
		RemainingMin:        types.Ptr(int(math.Round(float64(remaining) / 60_000))),
		CumulativeAvg:       cumulative,
		MarginalPerInstance: types.Ptr(float64(remaining) / float64(w)),
	}
	if current != nil && base != nil {
		out.FinalAvg = types.Ptr((*base*float64(elapsed) + float64(*current)*float64(remaining)) / float64(w))
	}
	return out
}

// AllowedInstanceType is the one EC2 type the task permits — the environment
// can override the task-sheet default when a variant names another.
func AllowedInstanceType() string {
	if v := strings.TrimSpace(os.Getenv("ALLOWED_INSTANCE_TYPE")); v != "" {
		return v
	}
	return DefaultAllowedType
}

// OffSpec is anything outside what the task allows. Existence alone is a
// penalty, so this reports facts (type, region, no cluster tag) and not a
// judgement about how bad they are.
func OffSpec(rows []types.InstanceRow, region string) []types.OffSpecInstance {
	out := []types.OffSpecInstance{}
	for _, r := range rows {
		reasons := []string{}
		if r.Type != "" && r.Type != AllowedInstanceType() {
			reasons = append(reasons, "타입 "+r.Type)
		}
		if r.AZ != "" && !strings.HasPrefix(r.AZ, region) {
			reasons = append(reasons, "리전 "+r.AZ)
		}
		if r.ClusterTag == nil {
			reasons = append(reasons, "클러스터에 속하지 않음")
		}
		if len(reasons) > 0 {
			out = append(out, types.OffSpecInstance{InstanceRow: r, Reason: strings.Join(reasons, " · ")})
		}
	}
	return out
}

// --- backfill ----------------------------------------------------------------

type TrailDelta struct {
	T     int64
	Delta int
}

// ParseTrailEvents turns CloudTrail's event stream into count deltas. One
// RunInstances can launch several instances, so the delta is the size of the
// instance set, not one per event.
func ParseTrailEvents(events []types.CloudTrailEvent) []TrailDelta {
	out := []TrailDelta{}
	for _, e := range events {
		sign := 0
		switch e.Name {
		case "RunInstances":
			sign = 1
		case "TerminateInstances":
			sign = -1
		}
		if sign == 0 || e.TsMs == 0 {
			continue
		}
		n := 1
		var body struct {
			ResponseElements struct {
				InstancesSet struct {
					Items []json.RawMessage `json:"items"`
				} `json:"instancesSet"`
			} `json:"responseElements"`
		}
		// A malformed event body still tells us one instance moved. Dropping
		// the event entirely would understate the count for the rest of the
		// window.
		if err := json.Unmarshal([]byte(e.Body), &body); err == nil {
			if count := len(body.ResponseElements.InstancesSet.Items); count > 0 {
				n = count
			}
		}
		out = append(out, TrailDelta{T: e.TsMs, Delta: sign * n})
	}
	return out
}

// Reconstruct walks the count backwards from a known present value.
//
// n(now) is what describe-instances just said. For an event at t with delta d,
// the count immediately before t is (count after t) − d. Emitting a sample at
// each event time gives the same step function the live poller would have
// recorded had it been running.
func Reconstruct(deltas []TrailDelta, currentCount int, fromMs, nowMs int64) []Sample {
	desc := []TrailDelta{}
	for _, d := range deltas {
		if d.T > fromMs && d.T <= nowMs {
			desc = append(desc, d)
		}
	}
	sort.SliceStable(desc, func(i, j int) bool { return desc[i].T > desc[j].T })

	out := []Sample{{T: nowMs, V: float64(currentCount)}}
	cur := currentCount
	for _, d := range desc {
		out = append(out, Sample{T: d.T, V: float64(cur)})
		cur -= d.Delta
	}
	out = append(out, Sample{T: fromMs, V: float64(cur)})

	// Counts cannot be negative. A negative here means CloudTrail and
	// describe-instances disagree — usually an instance terminated outside the
	// lookup window — and clamping is closer to the truth than a negative node.
	for i := range out {
		if out[i].V < 0 {
			out[i].V = 0
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].T < out[j].T })
	return out
}
