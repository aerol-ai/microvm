package service

// template_metrics_test.go pins the Phase 6 PR-C operator-visibility
// surface. expvar values are process globals, so each assertion takes a
// before/after delta rather than expecting absolute values — the same
// convention as internal/pool/vmm/metrics_test.go and
// pkg/capacity/admission_test.go.

import (
	"expvar"
	"strconv"
	"testing"
)

func intValue(v expvar.Var) int64 {
	if v == nil {
		return 0
	}
	n, _ := strconv.ParseInt(v.String(), 10, 64)
	return n
}

// TestRecordTemplatePushGauges_PartitionsByState proves the gauge
// sampler partitions the reconciler's pending list into per-state
// counts. The reconciler hands us the rows it already loaded; we must
// not invent counts (which would double-count under multiple ticks).
func TestRecordTemplatePushGauges_PartitionsByState(t *testing.T) {
	rows := []*templatePushGaugeRow{
		{PushState: "pending"},
		{PushState: "pending"},
		{PushState: "pending"},
		{PushState: "error"},
		{PushState: "error"},
		// 'pushing' rows should not surface — they're transient and the
		// gauge would blip per tick.
		{PushState: "pushing"},
	}
	recordTemplatePushGauges(rows)
	if got := intValue(templatePushPendingGauge); got != 3 {
		t.Errorf("pending gauge = %d, want 3", got)
	}
	if got := intValue(templatePushErrorGauge); got != 2 {
		t.Errorf("error gauge = %d, want 2", got)
	}
}

// TestRecordTemplatePushGauges_EmptyClears proves the gauge resets to
// zero when the pending queue drains. Without this, an operator's panel
// would show stale "5 templates failing to push" forever after the last
// row recovered.
func TestRecordTemplatePushGauges_EmptyClears(t *testing.T) {
	recordTemplatePushGauges([]*templatePushGaugeRow{
		{PushState: "pending"},
		{PushState: "error"},
	})
	recordTemplatePushGauges(nil)
	if got := intValue(templatePushPendingGauge); got != 0 {
		t.Errorf("pending gauge after empty sample = %d, want 0", got)
	}
	if got := intValue(templatePushErrorGauge); got != 0 {
		t.Errorf("error gauge after empty sample = %d, want 0", got)
	}
}

// TestAddTemplateUnhealthyGauge_TracksDelta proves the gauge tracks
// per-transition increments/decrements. MarkSnapshotCorrupt adds 1 on
// the first-observer transition; RebuildTemplateSnapshot subtracts 1
// on terminal state (ready or ready_no_snapshot). The startup scanner
// uses recordTemplateUnhealthyGauge to seed the count from the row
// count it fetched.
func TestAddTemplateUnhealthyGauge_TracksDelta(t *testing.T) {
	before := intValue(templateUnhealthyGauge)
	addTemplateUnhealthyGauge(2)
	addTemplateUnhealthyGauge(-1)
	if got := intValue(templateUnhealthyGauge); got != before+1 {
		t.Errorf("unhealthy gauge delta = %d, want %d (after +2 -1)", got-before, int64(1))
	}
	// Reset so subsequent tests in this binary don't inherit our delta.
	addTemplateUnhealthyGauge(-1)
}

// TestRecordTemplateUnhealthyGauge_AbsoluteSet proves the scanner's
// seed-the-gauge path replaces (not adds to) the current value. The
// startup scanner has the authoritative row count; partial-tick state
// from a previous in-process MarkSnapshotCorrupt must not leak across
// the reset.
func TestRecordTemplateUnhealthyGauge_AbsoluteSet(t *testing.T) {
	addTemplateUnhealthyGauge(7)
	recordTemplateUnhealthyGauge(3)
	if got := intValue(templateUnhealthyGauge); got != 3 {
		t.Errorf("unhealthy gauge after Set(3) = %d, want 3", got)
	}
	recordTemplateUnhealthyGauge(0)
}
