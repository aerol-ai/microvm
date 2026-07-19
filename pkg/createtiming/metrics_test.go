package createtiming

import (
	"expvar"
	"strconv"
	"testing"
	"time"
)

func expvarInt(v expvar.Var) int64 {
	if v == nil {
		return 0
	}
	n, _ := strconv.ParseInt(v.String(), 10, 64)
	return n
}

func nestedExpvarInt(root *expvar.Map, outer, inner string) int64 {
	sub, ok := root.Get(outer).(*expvar.Map)
	if !ok || sub == nil {
		return 0
	}
	return expvarInt(sub.Get(inner))
}

func TestRecordStageExportsHistogram(t *testing.T) {
	root, ok := expvar.Get("aerolvm_create_stage_latency_seconds_bucket").(*expvar.Map)
	if !ok || root == nil {
		t.Fatal("create stage histogram expvar missing")
	}
	// 42ms lands in the default le_50ms bound (not le_100ms).
	before := nestedExpvarInt(root, "fc_verify", "le_50ms")

	timing := &CreateTiming{}
	timing.RecordStage("fc_verify", 42*time.Millisecond)

	if got := nestedExpvarInt(root, "fc_verify", "le_50ms") - before; got != 1 {
		t.Fatalf("fc_verify le_50ms delta = %d, want 1", got)
	}
}

func BenchmarkRecordStageWithExport(b *testing.B) {
	timing := &CreateTiming{}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		timing.RecordStage("fc_verify", 42*time.Millisecond)
	}
}
