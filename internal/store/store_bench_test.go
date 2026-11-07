package store

import (
	"context"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Per-node store benchmarks. They answer one question: how much work can one
// node's SQLite store do, and what has to wait behind what? Each workload is a
// real caller:
//
//   - Create: the store write inside Service.CreateSandbox.
//   - GetUnderWrites: API reads (Get) while lifecycle writes (UpdateStatus) run.
//   - NetstatsTick: the network poller (netstatsServiceSink), which writes one
//     counter UPDATE and re-reads one row per active sandbox every
//     SB_NETSTATS_POLL_INTERVAL, while creates keep arriving.
//   - CreateDuringListSweep: creates while a full List runs in a loop
//     (reconcile, idle sweep and netstats target listing all call List).
//
// They need no network. Run them with a fixed count so the preload is paid a
// known number of times:
//
//	go test -run '^$' -bench BenchmarkStore -benchtime 200x ./internal/store/
//
// SB_STORE_BENCH_SANDBOXES sets how many sandbox rows each run starts with
// (default 2000, a dense worker).

const benchDefaultSandboxes = 2000

var (
	benchTemplateOnce sync.Once
	benchTemplatePath string
	benchTemplateIDs  []string
	benchTemplateErr  error
)

func benchSandboxCount() int {
	if v, err := strconv.Atoi(os.Getenv("SB_STORE_BENCH_SANDBOXES")); err == nil && v > 0 {
		return v
	}
	return benchDefaultSandboxes
}

// benchTemplate builds one preloaded database per process and hands every
// benchmark a private copy, so a run measures the workload and not the
// preload.
func benchTemplate(b *testing.B) (string, []string) {
	b.Helper()
	benchTemplateOnce.Do(func() {
		dir, err := os.MkdirTemp("", "aerolvm-store-bench-")
		if err != nil {
			benchTemplateErr = err
			return
		}
		path := filepath.Join(dir, "template.db")
		st, err := Open(path)
		if err != nil {
			benchTemplateErr = err
			return
		}
		ctx := context.Background()
		// Preload speed only; the copy each benchmark opens uses the
		// store's real settings.
		if _, err := st.db.ExecContext(ctx, `PRAGMA synchronous = OFF`); err != nil {
			benchTemplateErr = err
			return
		}
		n := benchSandboxCount()
		ids := make([]string, 0, n)
		for i := 0; i < n; i++ {
			sb := sampleSandbox(fmt.Sprintf("sb-bench-%06d", i))
			if err := st.Create(ctx, sb); err != nil {
				benchTemplateErr = err
				return
			}
			ids = append(ids, sb.ID)
		}
		if _, err := st.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
			benchTemplateErr = err
			return
		}
		if err := st.Close(); err != nil {
			benchTemplateErr = err
			return
		}
		benchTemplatePath, benchTemplateIDs = path, ids
	})
	if benchTemplateErr != nil {
		b.Fatalf("build bench template: %v", benchTemplateErr)
	}
	return benchTemplatePath, benchTemplateIDs
}

// benchOpen returns a store over a fresh copy of the preloaded template.
func benchOpen(b *testing.B) (*Store, []string) {
	b.Helper()
	src, ids := benchTemplate(b)
	dst := filepath.Join(b.TempDir(), "state.db")
	if err := copyBenchFile(src, dst); err != nil {
		b.Fatalf("copy template: %v", err)
	}
	st, err := Open(dst)
	if err != nil {
		b.Fatalf("Open: %v", err)
	}
	b.Cleanup(func() { _ = st.Close() })
	// SB_STORE_BENCH_SYNC=FULL measures what syncing the WAL on every commit
	// would cost. The writer pool holds one connection, so the PRAGMA sticks.
	if mode := os.Getenv("SB_STORE_BENCH_SYNC"); mode != "" {
		if _, err := st.db.ExecContext(context.Background(), `PRAGMA synchronous = `+mode); err != nil {
			b.Fatalf("set synchronous: %v", err)
		}
	}
	return st, ids
}

func copyBenchFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	return out.Close()
}

type benchLatencies struct {
	mu sync.Mutex
	d  []time.Duration
}

func (l *benchLatencies) add(d time.Duration) {
	l.mu.Lock()
	l.d = append(l.d, d)
	l.mu.Unlock()
}

// pct returns the p-th percentile in milliseconds (nearest rank).
func (l *benchLatencies) pct(p float64) float64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.d) == 0 {
		return 0
	}
	sorted := append([]time.Duration(nil), l.d...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	rank := int(math.Ceil(p/100*float64(len(sorted)))) - 1
	if rank < 0 {
		rank = 0
	}
	return float64(sorted[rank]) / float64(time.Millisecond)
}

func (l *benchLatencies) report(b *testing.B, name string) {
	b.ReportMetric(l.pct(50), name+"_p50_ms")
	b.ReportMetric(l.pct(99), name+"_p99_ms")
}

var benchCreateSeq atomic.Int64

func benchNewSandbox() *models.Sandbox {
	return sampleSandbox(fmt.Sprintf("sb-new-%d", benchCreateSeq.Add(1)))
}

// BenchmarkStoreCreate is one create at a time: the floor for a create's
// store cost on an idle node.
func BenchmarkStoreCreate(b *testing.B) {
	st, _ := benchOpen(b)
	ctx := context.Background()
	var lat benchLatencies
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb := benchNewSandbox()
		t0 := time.Now()
		if err := st.Create(ctx, sb); err != nil {
			b.Fatalf("Create: %v", err)
		}
		lat.add(time.Since(t0))
	}
	b.StopTimer()
	lat.report(b, "create")
}

// BenchmarkStoreCreateParallel is a create burst: many callers at once.
func BenchmarkStoreCreateParallel(b *testing.B) {
	st, _ := benchOpen(b)
	ctx := context.Background()
	var lat benchLatencies
	b.SetParallelism(4)
	b.ResetTimer()
	start := time.Now()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			sb := benchNewSandbox()
			t0 := time.Now()
			if err := st.Create(ctx, sb); err != nil {
				b.Errorf("Create: %v", err)
				return
			}
			lat.add(time.Since(t0))
		}
	})
	elapsed := time.Since(start)
	b.StopTimer()
	lat.report(b, "create")
	b.ReportMetric(float64(b.N)/elapsed.Seconds(), "creates/s")
}

// BenchmarkStoreGetUnderWrites measures API reads while four writers keep
// changing sandbox rows.
func BenchmarkStoreGetUnderWrites(b *testing.B) {
	st, ids := benchOpen(b)
	ctx := context.Background()
	stop := make(chan struct{})
	var writes atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := w; ; i += 4 {
				select {
				case <-stop:
					return
				default:
				}
				if err := st.UpdateStatus(ctx, ids[i%len(ids)], models.SandboxStatusStarted, ""); err != nil {
					b.Errorf("UpdateStatus: %v", err)
					return
				}
				writes.Add(1)
			}
		}(w)
	}
	var lat benchLatencies
	var next atomic.Int64
	b.ResetTimer()
	start := time.Now()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			id := ids[int(next.Add(1))%len(ids)]
			t0 := time.Now()
			if _, err := st.Get(ctx, id); err != nil {
				b.Errorf("Get: %v", err)
				return
			}
			lat.add(time.Since(t0))
		}
	})
	elapsed := time.Since(start)
	b.StopTimer()
	close(stop)
	wg.Wait()
	lat.report(b, "get")
	b.ReportMetric(float64(b.N)/elapsed.Seconds(), "gets/s")
	b.ReportMetric(float64(writes.Load())/elapsed.Seconds(), "writes/s")
}

// benchNetstatsTick replays the store traffic of one netstats poll over
// every active sandbox, the way netstatsServiceSink.handleNetworkSamples
// does it: one ApplyNetCounterDeltas call. No sandbox has a cap, so there
// is no quota re-read.
func benchNetstatsTick(ctx context.Context, st *Store, ids []string) error {
	deltas := make([]NetCounterDelta, len(ids))
	for i, id := range ids {
		deltas[i] = NetCounterDelta{SandboxID: id, BytesIn: 1500, BytesOut: 900}
	}
	_, err := st.ApplyNetCounterDeltas(ctx, deltas)
	return err
}

// BenchmarkStoreNetstatsTick runs netstats ticks over every preloaded
// sandbox while a paced client creates 100 sandboxes per second, and reports
// how long a tick takes and how long creates wait meanwhile.
func BenchmarkStoreNetstatsTick(b *testing.B) {
	st, ids := benchOpen(b)
	ctx := context.Background()
	stop := make(chan struct{})
	var createLat benchLatencies
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		pace := time.NewTicker(10 * time.Millisecond)
		defer pace.Stop()
		for {
			select {
			case <-stop:
				return
			case <-pace.C:
			}
			sb := benchNewSandbox()
			t0 := time.Now()
			if err := st.Create(ctx, sb); err != nil {
				b.Errorf("Create: %v", err)
				return
			}
			createLat.add(time.Since(t0))
		}
	}()
	var tickLat benchLatencies
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		t0 := time.Now()
		if err := benchNetstatsTick(ctx, st, ids); err != nil {
			b.Fatalf("netstats tick: %v", err)
		}
		tickLat.add(time.Since(t0))
	}
	b.StopTimer()
	close(stop)
	wg.Wait()
	b.ReportMetric(tickLat.pct(50), "tick_p50_ms")
	createLat.report(b, "create")
}

// BenchmarkStoreCreateDuringListSweep measures creates while a background
// loop lists every sandbox, as the reconcile and idle sweeps do.
func BenchmarkStoreCreateDuringListSweep(b *testing.B) {
	st, _ := benchOpen(b)
	ctx := context.Background()
	stop := make(chan struct{})
	var sweeps atomic.Int64
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := st.List(ctx); err != nil {
				b.Errorf("List: %v", err)
				return
			}
			sweeps.Add(1)
		}
	}()
	var lat benchLatencies
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		sb := benchNewSandbox()
		t0 := time.Now()
		if err := st.Create(ctx, sb); err != nil {
			b.Fatalf("Create: %v", err)
		}
		lat.add(time.Since(t0))
	}
	elapsed := time.Since(start)
	b.StopTimer()
	close(stop)
	wg.Wait()
	lat.report(b, "create")
	b.ReportMetric(float64(sweeps.Load())/elapsed.Seconds(), "sweeps/s")
}
