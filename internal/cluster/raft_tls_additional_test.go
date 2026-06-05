package cluster

import (
	"crypto/tls"
	"log/slog"
	"os"
	"testing"
)

func TestSetupRaftTLSAndBootstrap(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	fsm := newPlacementFSM()
	dir := t.TempDir()

	tlsConfig := &ClusterTLS{
		// use unexported fields since this is in the same package
		nodeCert: tls.Certificate{},
	}

	rn, err := setupRaft(raftSetupConfig{
		NodeID:           "node1",
		DataDir:          dir,
		BindAddr:         "127.0.0.1:0",
		BootstrapCluster: true,
		TLS:              tlsConfig,
	}, fsm, logger)

	if err == nil {
		rn.Close()
	}
}

func TestSetupRaftTLSBadAddr(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	fsm := newPlacementFSM()
	dir := t.TempDir()

	_, _ = setupRaft(raftSetupConfig{
		NodeID:   "node1",
		DataDir:  dir,
		BindAddr: "invalid-bind:xyz",
		TLS:      &ClusterTLS{},
	}, fsm, logger)
}
