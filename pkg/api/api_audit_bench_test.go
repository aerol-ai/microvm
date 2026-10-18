package api

// Benchmark and CI budget for writing one api record (CEO review D21).
//
// Budget: p99 <= 5µs per recorded call, measured through the whole audit
// seam around a no-op handler: reading the route off the pattern, the call
// state, the recording writer, building the record (caller, request, the
// sandbox's identity from the cache) and handing it to the writer. The
// writer here only counts, so the number is the request path's cost, not
// the disk's: the real writer takes the record off a buffered channel on
// its own goroutine. TestAPIRecordEmitLatencyBudget enforces it in CI's
// coverage job (AEROLVM_SCALE_GATES=1), never under -race.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/auditlog"
	"github.com/aerol-ai/microvm/pkg/controlplane"
)

const apiRecordEmitBudgetP99 = 5 * time.Microsecond

// countSink is a writer that keeps nothing.
type countSink struct{ n atomic.Int64 }

func (c *countSink) Emit(auditlog.Event) { c.n.Add(1) }

// newAPIRecordBench is an exec call on a sandbox, the most frequent kind
// of recorded call, behind recordRoute with a handler that does nothing.
func newAPIRecordBench(tb testing.TB) (serve func(), sink *countSink) {
	tb.Helper()
	svc := service.New(config.Config{}, discardLogger(), nil, nil, nil, nil, nil, nil, nil)
	sink = &countSink{}
	svc.UseAuditSinkForTest(sink)
	srv := NewServer(discardLogger(), svc, nil, nil, config.Config{}, "pat-token", nil)
	access := controlplane.OperatorAccess()
	call := apihttp.RouteCall{Permission: controlplane.PermSandboxExec, Access: access, HasAccess: true, Allowed: true}
	base := httptest.NewRequest(http.MethodGet, "/v1/sandboxes/sb-bench/toolbox/files/download", nil)
	base.Pattern = "/v1/sandboxes/{id}/toolbox/{path...}"
	base.SetPathValue("id", "sb-bench")
	base.SetPathValue("path", "files/download")
	base = base.WithContext(auditlog.ContextWithCorrelationID(controlplane.ContextWithAccess(base.Context(), access), "corr-bench"))
	w := &nopWriter{h: http.Header{}}
	noop := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	serve = func() { srv.recordRoute(w, base, call, noop) }
	serve()
	if sink.n.Load() != 1 {
		tb.Fatalf("setup call wrote %d records, want 1", sink.n.Load())
	}
	return serve, sink
}

func BenchmarkAPIRecordEmit(b *testing.B) {
	serve, _ := newAPIRecordBench(b)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		serve()
	}
}

// TestAPIRecordEmitLatencyBudget is the D21 CI gate for the api recorder.
// Each attempt takes many samples; a shared runner can stall any single
// one, so it passes on the first of three attempts within budget.
func TestAPIRecordEmitLatencyBudget(t *testing.T) {
	if os.Getenv("AEROLVM_SCALE_GATES") != "1" {
		t.Skip("set AEROLVM_SCALE_GATES=1 to run the api record latency budget")
	}
	if raceEnabled {
		t.Skip("the race detector makes timings meaningless")
	}
	serve, _ := newAPIRecordBench(t)
	for i := 0; i < 1000; i++ {
		serve()
	}
	const samples = 20000
	var p99 time.Duration
	for attempt := 0; attempt < 3; attempt++ {
		durations := make([]time.Duration, samples)
		for i := range durations {
			start := time.Now()
			serve()
			durations[i] = time.Since(start)
		}
		slices.Sort(durations)
		p99 = durations[samples*99/100]
		if p99 <= apiRecordEmitBudgetP99 {
			t.Logf("api record p99 = %v (budget %v)", p99, apiRecordEmitBudgetP99)
			return
		}
	}
	t.Fatalf("api record p99 = %v over three attempts, budget %v", p99, apiRecordEmitBudgetP99)
}
