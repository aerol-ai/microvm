package cluster

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
)

func TestMaybeRecoverRaftClusterSuccessPath(t *testing.T) {
	dir := t.TempDir()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fsm := newPlacementFSM()
	rn, err := setupRaft(raftSetupConfig{
		NodeID:           "n1",
		BindAddr:         "127.0.0.1:0",
		DataDir:          dir,
		BootstrapCluster: true,
	}, fsm, logger)
	if err != nil {
		t.Fatal(err)
	}
	// Wait until bootstrapped leadership so log/stable have initial state.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && rn.raft.State() != raft.Leader {
		time.Sleep(20 * time.Millisecond)
	}
	if rn.raft.State() != raft.Leader {
		t.Fatal("bootstrap did not elect leader")
	}
	addr := string(rn.transport.LocalAddr())
	if err := rn.Close(); err != nil {
		t.Fatal(err)
	}

	peers := fmt.Sprintf(`[{"id":"n1","address":%q}]`, addr)
	path := raftRecoveryPeersPath(dir)
	if err := os.WriteFile(path, []byte(peers), 0o600); err != nil {
		t.Fatal(err)
	}
	logStore, err := openRaftLogStore(dir, logger)
	if err != nil {
		t.Fatal(err)
	}
	defer logStore.Close()
	stable, err := raftboltdb.NewBoltStore(filepath.Join(dir, raftStableFilename))
	if err != nil {
		t.Fatal(err)
	}
	defer stable.Close()
	snaps, err := raft.NewFileSnapshotStore(dir, 1, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	_, transport := raft.NewInmemTransport(raft.ServerAddress(addr))
	rcfg := raft.DefaultConfig()
	rcfg.LocalID = raft.ServerID("n1")
	if err := maybeRecoverRaftClusterFromPeersFile(
		raftSetupConfig{DataDir: dir}, rcfg, fsm, logStore, stable, snaps, transport, logger,
	); err != nil {
		t.Fatalf("recover success: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("peers file should be renamed away, err=%v", err)
	}
}

func TestRaftNodeCloseNilParts(t *testing.T) {
	rn := &raftNode{}
	if err := rn.Close(); err != nil {
		t.Fatalf("nil Close: %v", err)
	}
}
