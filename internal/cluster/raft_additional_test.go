package cluster

import (
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/raft"
)

// BenchmarkFSMSnapshot is what one snapshot costs, the number the cadence in
// raft.go is set against: ns/op is how long Snapshot holds up Apply (raft
// calls the two from one goroutine), and MiB is what Persist then writes.
func BenchmarkFSMSnapshot(b *testing.B) {
	for _, n := range []int{10_000, 100_000} {
		b.Run(fmt.Sprintf("placements=%d", n), func(b *testing.B) {
			fsm := newPlacementFSM()
			fillFSMWithPlacements(b, fsm, n)
			var size int
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				snap, err := fsm.Snapshot()
				if err != nil {
					b.Fatal(err)
				}
				b.StopTimer()
				var sink memSnapshotSink
				if err := snap.Persist(&sink); err != nil {
					b.Fatal(err)
				}
				size = sink.Len()
				snap.Release()
				b.StartTimer()
			}
			b.ReportMetric(float64(size)/(1<<20), "MiB")
		})
	}
}

// Regression: raft snapshotted every 1,024 entries, checked every 30 s.
// Each snapshot holds up Apply while it copies every placement (91 ms at
// 100k placements), and the shorter cadence never made the log smaller:
// raft keeps TrailingLogs entries after each snapshot regardless.
func TestNewRaftConfigSnapshotCadence(t *testing.T) {
	c := newRaftConfig("node1", slog.New(slog.DiscardHandler))
	if c.SnapshotInterval != 120*time.Second || c.SnapshotThreshold != 8192 {
		t.Fatalf("snapshot cadence = %v / %d entries, want 120s / 8192", c.SnapshotInterval, c.SnapshotThreshold)
	}
	if c.TrailingLogs != 10240 {
		t.Fatalf("TrailingLogs = %d: the log kept after a snapshot changed; re-check the cadence comment in raft.go", c.TrailingLogs)
	}
	if c.LocalID != "node1" || c.Logger == nil {
		t.Fatalf("LocalID %q, logger %v", c.LocalID, c.Logger)
	}
	if err := raft.ValidateConfig(c); err != nil {
		t.Fatal(err)
	}
}

func TestSetupRaftErrors(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	fsm := newPlacementFSM()

	// Missing NodeID
	_, err := setupRaft(raftSetupConfig{}, fsm, logger)
	if err == nil {
		t.Errorf("expected error for missing NodeID")
	}

	// Bad DataDir
	_, err = setupRaft(raftSetupConfig{
		NodeID:  "node1",
		DataDir: "/dev/null/bad-dir", // mkdir will fail
	}, fsm, logger)
	if err == nil {
		t.Errorf("expected error for bad DataDir")
	}

	// Bad advertise addr
	dir := t.TempDir()
	_, err = setupRaft(raftSetupConfig{
		NodeID:        "node1",
		DataDir:       dir,
		BindAddr:      "127.0.0.1:0",
		AdvertiseAddr: "invalid-addr:port:bad",
	}, fsm, logger)
	if err == nil {
		t.Errorf("expected error for bad AdvertiseAddr")
	}

	// Bad bind addr (cannot listen)
	_, err = setupRaft(raftSetupConfig{
		NodeID:   "node1",
		DataDir:  dir,
		BindAddr: "invalid-bind:xyz",
	}, fsm, logger)
	if err == nil {
		t.Errorf("expected error for bad BindAddr")
	}
}

func TestSetupRaftSuccessAndClose(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	fsm := newPlacementFSM()
	dir := t.TempDir()

	rn, err := setupRaft(raftSetupConfig{
		NodeID:   "node1",
		DataDir:  dir,
		BindAddr: "127.0.0.1:0", // random port
	}, fsm, logger)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rn == nil {
		t.Fatalf("expected non-nil raftNode")
	}

	err = rn.Close()
	if err != nil {
		t.Errorf("unexpected close error: %v", err)
	}

	// test closing an empty struct
	emptyRn := &raftNode{}
	emptyRn.Close()
}

func TestHclogAdapter(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	adapter := hclogAdapter(logger)
	adapter.Info("test hclog")

	// Test writer directly
	w := hclogWriter{l: logger}
	w.Write([]byte("test write"))
}
