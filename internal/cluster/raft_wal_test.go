package cluster

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
)

func TestDetectRaftLogStoreFormat(t *testing.T) {
	dir := t.TempDir()
	if got := detectRaftLogStoreFormat(dir); got != "wal" {
		t.Fatalf("empty dir format = %q, want wal", got)
	}

	boltPath := filepath.Join(dir, raftLogBoltFilename)
	if err := os.WriteFile(boltPath, []byte{0}, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := detectRaftLogStoreFormat(dir); got != "bolt" {
		t.Fatalf("bolt-present format = %q, want bolt", got)
	}

	// A directory named raft-log.bolt is a corrupt layout — open must error,
	// not fall through to WAL.
	dir2 := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir2, raftLogBoltFilename), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := openRaftLogStore(dir2, slog.Default()); err == nil {
		t.Fatal("expected error when raft-log.bolt is a directory")
	}
}

func TestOpenRaftLogStoreWAL(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()
	store, err := openRaftLogStore(dir, logger)
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	defer store.Close()
	if detectRaftLogStoreFormat(dir) != "wal" {
		t.Fatal("expected wal detection after open")
	}
	if _, err := store.FirstIndex(); err != nil {
		t.Fatalf("FirstIndex: %v", err)
	}
}

func TestOpenRaftLogStoreBoltWhenPresent(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()
	boltPath := filepath.Join(dir, raftLogBoltFilename)
	seed, err := openBoltLogStoreForTest(boltPath)
	if err != nil {
		t.Fatalf("seed bolt: %v", err)
	}
	_ = seed.Close()

	reopened, err := openRaftLogStore(dir, logger)
	if err != nil {
		t.Fatalf("reopen bolt: %v", err)
	}
	defer reopened.Close()
	if detectRaftLogStoreFormat(dir) != "bolt" {
		t.Fatal("expected bolt detection")
	}
}

func TestSetupRaftWALRoundTrip(t *testing.T) {
	dir := t.TempDir()
	logger := slog.Default()
	fsm := newPlacementFSM()
	rn, err := setupRaft(raftSetupConfig{
		NodeID:           "n1",
		BindAddr:         "127.0.0.1:0",
		DataDir:          dir,
		BootstrapCluster: true,
	}, fsm, logger)
	if err != nil {
		t.Fatalf("setupRaft wal: %v", err)
	}
	// Wait briefly for bootstrap leadership so StoreLogs path is live.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if rn.raft.State() == raft.Leader {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := rn.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Restart on the same WAL dir — format detection must stay on WAL
	// (no bolt file) and recovery must use the matching store.
	fsm2 := newPlacementFSM()
	rn2, err := setupRaft(raftSetupConfig{
		NodeID:           "n1",
		BindAddr:         "127.0.0.1:0",
		DataDir:          dir,
		BootstrapCluster: true,
	}, fsm2, logger)
	if err != nil {
		t.Fatalf("restart setupRaft: %v", err)
	}
	defer rn2.Close()
	if detectRaftLogStoreFormat(dir) != "wal" {
		t.Fatal("restart must keep wal format")
	}
}

func TestMixedFormatRecoveryUsesMatchingStore(t *testing.T) {
	// Bolt node: seed bolt log, then recover with peers.json using the
	// same store type openRaftLogStore selected.
	dir := t.TempDir()
	logger := slog.Default()
	boltPath := filepath.Join(dir, raftLogBoltFilename)
	seed, err := openBoltLogStoreForTest(boltPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = seed.Close()

	store, err := openRaftLogStore(dir, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if detectRaftLogStoreFormat(dir) != "bolt" {
		t.Fatal("mixed-format bolt node must open bolt")
	}
}

func openBoltLogStoreForTest(path string) (closableLogStore, error) {
	return raftboltdb.NewBoltStore(path)
}

func TestOpenRaftLogStoreErrorPaths(t *testing.T) {
	logger := slog.Default()

	// Corrupt bolt file that BoltStore refuses.
	dir := t.TempDir()
	boltPath := filepath.Join(dir, raftLogBoltFilename)
	if err := os.WriteFile(boltPath, []byte("not-a-bolt-db"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openRaftLogStore(dir, logger); err == nil {
		t.Fatal("want bolt open error on corrupt file")
	}

	// WAL mkdir failure: dataDir not writable.
	dir2 := t.TempDir()
	if err := os.Chmod(dir2, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir2, 0o700) })
	if _, err := openRaftLogStore(dir2, logger); err == nil {
		t.Fatal("want mkdir wal dir error on read-only dataDir")
	}

	// nil logger still opens WAL.
	dir3 := t.TempDir()
	store, err := openRaftLogStore(dir3, nil)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
}

func TestRaftNodeCloseNilFields(t *testing.T) {
	// Empty node — Close must be nil-safe and return nil.
	rn := &raftNode{}
	if err := rn.Close(); err != nil {
		t.Fatalf("Close empty = %v", err)
	}
}
