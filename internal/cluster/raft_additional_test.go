package cluster

import (
	"log/slog"
	"os"
	"testing"
)

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
