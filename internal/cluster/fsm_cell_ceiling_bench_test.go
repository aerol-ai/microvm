package cluster

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

// BenchmarkFSMCellCeiling is the offline half of Phase 0 spike S4
// (plans/kubernetes-v2-architecture.md §18): what one cell's placement FSM
// costs as it grows. Per size it reports
//
//   - apply-us: one opPlace on an FSM already that full. Raft applies on one
//     goroutine, so 1e6/apply-us bounds a cell's creates per second however
//     fast the log commits (BenchmarkReserveCommit measures the commit side).
//   - snapshot-ms: how long Snapshot holds up Apply.
//   - MiB and persist-ms: what a snapshot writes, and how long writing takes.
//   - restore-ms: a follower's resync, or a cold start, from that snapshot.
//   - heap-MiB: live heap of one FSM at that size, after a GC.
//
// Every placement also holds one raw-TCP port (fillFSMWithPlacements), which
// makes the numbers heavier than a typical cell's. The default size keeps a
// plain -bench run short; S4 sets its sizes:
//
//	AEROL_S4_PLACEMENTS=100000,250000,1000000 go test -run '^$' \
//	  -bench BenchmarkFSMCellCeiling -benchtime 1x -timeout 60m ./internal/cluster/
func BenchmarkFSMCellCeiling(b *testing.B) {
	sizes, err := cellCeilingSizes(os.Getenv("AEROL_S4_PLACEMENTS"))
	if err != nil {
		b.Fatal(err)
	}
	for _, n := range sizes {
		b.Run(fmt.Sprintf("placements=%d", n), func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				m := measureCellCeiling(b, n, 2_000)
				b.ReportMetric(m.applyMicros, "apply-us")
				b.ReportMetric(float64(m.snapshot.Milliseconds()), "snapshot-ms")
				b.ReportMetric(float64(m.persist.Milliseconds()), "persist-ms")
				b.ReportMetric(float64(m.snapshotBytes)/(1<<20), "MiB")
				b.ReportMetric(float64(m.restore.Milliseconds()), "restore-ms")
				b.ReportMetric(float64(m.heapBytes)/(1<<20), "heap-MiB")
			}
		})
	}
}

type cellCeiling struct {
	applyMicros            float64
	snapshot, persist      time.Duration
	restore                time.Duration
	snapshotBytes          int
	heapBytes              uint64
	placementsAfterRestore int
}

// measureCellCeiling fills an FSM with n placements, times `probes` more
// opPlace applies on it, then snapshots it and restores the snapshot into a
// fresh FSM.
func measureCellCeiling(tb testing.TB, n, probes int) cellCeiling {
	tb.Helper()
	var m cellCeiling
	fsm := newPlacementFSM()
	fillFSMWithPlacements(tb, fsm, n)

	next := uint64(2*n + 1)
	start := time.Now()
	for j := range probes {
		id := fmt.Sprintf("probe-%07d", j)
		data, _ := encodeCommand(command{
			Op:            opPlace,
			SandboxID:     id,
			OwnerNodeID:   fmt.Sprintf("node-%03d", j%32),
			OwnerAPIURL:   "http://10.1.0.1:21212",
			Spec:          &models.CreateSandboxRequest{Image: "img"},
			IncarnationID: "inc-" + id,
		})
		if got := fsm.Apply(&raft.Log{Index: next, Data: data}); got != nil {
			tb.Fatalf("probe place %d: %v", j, got)
		}
		next++
	}
	m.applyMicros = float64(time.Since(start).Microseconds()) / float64(probes)

	runtime.GC()
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	m.heapBytes = ms.HeapAlloc

	start = time.Now()
	snap, err := fsm.Snapshot()
	if err != nil {
		tb.Fatal(err)
	}
	m.snapshot = time.Since(start)
	var sink memSnapshotSink
	start = time.Now()
	if err := snap.Persist(&sink); err != nil {
		tb.Fatal(err)
	}
	m.persist = time.Since(start)
	snap.Release()
	m.snapshotBytes = sink.Len()

	restored := newPlacementFSM()
	start = time.Now()
	if err := restored.Restore(io.NopCloser(bytes.NewReader(sink.Bytes()))); err != nil {
		tb.Fatal(err)
	}
	m.restore = time.Since(start)
	restored.mu.RLock()
	m.placementsAfterRestore = len(restored.placements)
	restored.mu.RUnlock()
	return m
}

// cellCeilingSizes parses AEROL_S4_PLACEMENTS ("100000,250000"); empty means
// one small size.
func cellCeilingSizes(v string) ([]int, error) {
	if strings.TrimSpace(v) == "" {
		return []int{10_000}, nil
	}
	var sizes []int
	for f := range strings.SplitSeq(v, ",") {
		n, err := strconv.Atoi(strings.TrimSpace(f))
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("AEROL_S4_PLACEMENTS: %q is not a positive count", f)
		}
		sizes = append(sizes, n)
	}
	return sizes, nil
}

// The S4 numbers are only as good as the restore they time: a restore that
// dropped rows would look fast.
func TestMeasureCellCeilingRestoresEveryPlacement(t *testing.T) {
	m := measureCellCeiling(t, 500, 10)
	if want := 500 + 10; m.placementsAfterRestore != want {
		t.Fatalf("restored %d placements, want %d", m.placementsAfterRestore, want)
	}
	if m.snapshotBytes == 0 || m.applyMicros <= 0 {
		t.Fatalf("empty measurement: %+v", m)
	}
}

func TestCellCeilingSizes(t *testing.T) {
	for _, tc := range []struct {
		in      string
		want    []int
		wantErr bool
	}{
		{"", []int{10_000}, false},
		{" 100000, 250000 ", []int{100_000, 250_000}, false},
		{"100k", nil, true},
		{"0", nil, true},
	} {
		got, err := cellCeilingSizes(tc.in)
		if (err != nil) != tc.wantErr || fmt.Sprint(got) != fmt.Sprint(tc.want) {
			t.Errorf("cellCeilingSizes(%q) = %v, %v; want %v (error %v)", tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}
