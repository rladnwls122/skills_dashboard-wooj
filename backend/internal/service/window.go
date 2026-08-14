package service

import (
	"fmt"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

// The one time window every panel reads. Ported from src/lib/server/window.ts —
// the rules are unchanged:
//
//   - The span is capped at 4 hours. Insights bills per byte scanned.
//   - Only span/interval pairs producing 4..250 buckets are offered.
//   - The end is floored to an interval boundary, so every bucket is complete.
//     A partial trailing bucket reads as a sudden drop.
var (
	windowChoicesMin   = []int{15, 30, 60, 120, 240}
	intervalChoicesMin = []int{1, 5, 10, 60}
)

const (
	minBuckets = 4
	maxBuckets = 250
)

var defaultWindow = types.WindowSelection{WindowMin: 60, IntervalMin: 1}

func validIntervals(windowMin int) []int {
	out := []int{}
	for _, i := range intervalChoicesMin {
		if windowMin%i != 0 {
			continue
		}
		b := windowMin / i
		if b >= minBuckets && b <= maxBuckets {
			out = append(out, i)
		}
	}
	return out
}

func windowLabel(windowMin int) string {
	if windowMin%60 == 0 {
		return fmt.Sprintf("%dh", windowMin/60)
	}
	return fmt.Sprintf("%dm", windowMin)
}

// ResolveWindow turns a selection into concrete bounds. Invalid input is
// corrected rather than rejected — a stale bookmark should still render, and the
// correction is visible because the resolved window is what the UI labels.
func ResolveWindow(sel *types.WindowSelection, nowMs int64) types.ResolvedWindow {
	windowMin := defaultWindow.WindowMin
	if sel != nil {
		for _, w := range windowChoicesMin {
			if sel.WindowMin == w {
				windowMin = w
				break
			}
		}
	}
	allowed := validIntervals(windowMin)
	intervalMin := 1
	if len(allowed) > 0 {
		intervalMin = allowed[0]
	}
	if sel != nil {
		for _, i := range allowed {
			if sel.IntervalMin == i {
				intervalMin = i
				break
			}
		}
	}

	intervalMs := int64(intervalMin) * 60_000
	endMs := nowMs / intervalMs * intervalMs
	return types.ResolvedWindow{
		WindowMin:   windowMin,
		IntervalMin: intervalMin,
		StartMs:     endMs - int64(windowMin)*60_000,
		EndMs:       endMs,
		Buckets:     windowMin / intervalMin,
		Label:       fmt.Sprintf("%s / %dm", windowLabel(windowMin), intervalMin),
	}
}
