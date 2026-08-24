package live

// The one-shot CloudTrail backfill behind the 노드 비용 panel. It gets exactly
// one attempt per process, so what counts as an attempt matters.

import (
	"context"
	"testing"

	"github.com/rladnwls122/skills_dashboard-wooj/backend/internal/types"
)

func TestBackfillDoesNotSpendItsOneShotBeforeTheWindowOpens(t *testing.T) {
	nowMs := int64(1_700_000_000_000)
	provider := &Provider{}

	// The panel is opened before the scoring window starts: there is nothing to
	// reconstruct, so this must not count as the one attempt. It used to, and
	// the stretch the dashboard was not running for then stayed empty for the
	// rest of the process's life with no note explaining it.
	notStarted := types.ScoringWindow{StartMs: nowMs + 60_000, EndMs: nowMs + 3*3600_000}
	if note := provider.backfillOnce(context.Background(), notStarted, 3, nowMs); note != "" {
		t.Fatalf("expected no note before the window opens, got %q", note)
	}
	if provider.backfill.attempted {
		t.Fatal("a window with nothing to fill must not consume the one-shot attempt")
	}

	// A window that ends exactly at now is the same case — zero span, nothing
	// to reconstruct.
	empty := types.ScoringWindow{StartMs: nowMs, EndMs: nowMs}
	if note := provider.backfillOnce(context.Background(), empty, 3, nowMs); note != "" {
		t.Fatalf("expected no note for an empty span, got %q", note)
	}
	if provider.backfill.attempted {
		t.Fatal("an empty span must not consume the one-shot attempt")
	}
}

func TestBackfillReportsTheSameNoteWithoutRetrying(t *testing.T) {
	nowMs := int64(1_700_000_000_000)
	provider := &Provider{}
	// A real attempt has already happened and failed. AWS is nil here, so a
	// second attempt would panic — which is precisely the assertion: the guard
	// has to short-circuit before anything is queried again.
	provider.backfill.attempted = true
	provider.backfill.note = "CloudTrail 조회에 실패"

	open := types.ScoringWindow{StartMs: nowMs - 3*3600_000, EndMs: nowMs}
	if note := provider.backfillOnce(context.Background(), open, 3, nowMs); note != "CloudTrail 조회에 실패" {
		t.Fatalf("memoized note not returned, got %q", note)
	}
}
