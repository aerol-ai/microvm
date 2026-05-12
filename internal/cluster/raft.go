package cluster

import (
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
)

// raftNode wraps the raft instance plus its on-disk stores so Close can shut
// them down in the right order.
type raftNode struct {
	raft      *raft.Raft
	transport *raft.NetworkTransport
	logStore  *raftboltdb.BoltStore
	stableStr *raftboltdb.BoltStore
	snaps     raft.SnapshotStore
}

// raftSetupConfig captures the inputs setupRaft needs.
type raftSetupConfig struct {
	NodeID           string
	BindAddr         string // listen address for raft TCP transport
	AdvertiseAddr    string // address peers should reach us at
	DataDir          string // directory for log/stable/snapshot stores
	BootstrapCluster bool   // single-node bootstrap flag
}

// setupRaft starts a raft node with the placement FSM. On success the caller
// owns shutdown via raftNode.Close.
func setupRaft(cfg raftSetupConfig, fsm *placementFSM, logger *slog.Logger) (*raftNode, error) {
	if cfg.NodeID == "" {
		return nil, fmt.Errorf("raft setup: NodeID required")
	}
	if cfg.AdvertiseAddr == "" {
		cfg.AdvertiseAddr = cfg.BindAddr
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, fmt.Errorf("raft setup: mkdir %s: %w", cfg.DataDir, err)
	}

	rcfg := raft.DefaultConfig()
	rcfg.LocalID = raft.ServerID(cfg.NodeID)
	// Bridge raft's hclog to our slog. We accept some log-level lossiness in
	// exchange for not running two log destinations.
	rcfg.Logger = hclogAdapter(logger)
	// More aggressive snapshotting than the default keeps the BoltDB log small
	// at high create/destroy churn. 1024 entries ~= a few seconds of churn at
	// peak; trades disk I/O for memory and faster follower recovery.
	rcfg.SnapshotInterval = 30 * time.Second
	rcfg.SnapshotThreshold = 1024

	logStore, err := raftboltdb.NewBoltStore(filepath.Join(cfg.DataDir, "raft-log.bolt"))
	if err != nil {
		return nil, fmt.Errorf("raft setup: bolt log store: %w", err)
	}
	stableStore, err := raftboltdb.NewBoltStore(filepath.Join(cfg.DataDir, "raft-stable.bolt"))
	if err != nil {
		_ = logStore.Close()
		return nil, fmt.Errorf("raft setup: bolt stable store: %w", err)
	}
	snaps, err := raft.NewFileSnapshotStoreWithLogger(cfg.DataDir, 3, hclogAdapter(logger))
	if err != nil {
		_ = logStore.Close()
		_ = stableStore.Close()
		return nil, fmt.Errorf("raft setup: snapshot store: %w", err)
	}

	advertise, err := net.ResolveTCPAddr("tcp", cfg.AdvertiseAddr)
	if err != nil {
		_ = logStore.Close()
		_ = stableStore.Close()
		return nil, fmt.Errorf("raft setup: resolve advertise addr %q: %w", cfg.AdvertiseAddr, err)
	}
	transport, err := raft.NewTCPTransportWithLogger(cfg.BindAddr, advertise, 3, 10*time.Second, hclogAdapter(logger))
	if err != nil {
		_ = logStore.Close()
		_ = stableStore.Close()
		return nil, fmt.Errorf("raft setup: tcp transport on %q: %w", cfg.BindAddr, err)
	}

	r, err := raft.NewRaft(rcfg, fsm, logStore, stableStore, snaps, transport)
	if err != nil {
		_ = transport.Close()
		_ = logStore.Close()
		_ = stableStore.Close()
		return nil, fmt.Errorf("raft setup: NewRaft: %w", err)
	}

	if cfg.BootstrapCluster {
		bootstrap := raft.Configuration{
			Servers: []raft.Server{{
				ID:      raft.ServerID(cfg.NodeID),
				Address: transport.LocalAddr(),
			}},
		}
		// BootstrapCluster errors when state already exists — that's fine on
		// restart of a previously-bootstrapped node, ignore via type-check.
		f := r.BootstrapCluster(bootstrap)
		if err := f.Error(); err != nil && err != raft.ErrCantBootstrap {
			logger.Warn("raft bootstrap returned non-fatal error", "err", err)
		}
	}

	return &raftNode{
		raft:      r,
		transport: transport,
		logStore:  logStore,
		stableStr: stableStore,
		snaps:     snaps,
	}, nil
}

func (r *raftNode) Close() error {
	// Order matters: shut raft first (it will stop using the transport and
	// stores), then close transport + stores.
	var firstErr error
	if r.raft != nil {
		if err := r.raft.Shutdown().Error(); err != nil {
			firstErr = fmt.Errorf("raft shutdown: %w", err)
		}
	}
	if r.transport != nil {
		_ = r.transport.Close()
	}
	if r.logStore != nil {
		if err := r.logStore.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close log store: %w", err)
		}
	}
	if r.stableStr != nil {
		if err := r.stableStr.Close(); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("close stable store: %w", err)
		}
	}
	return firstErr
}

// hclogAdapter wraps an *slog.Logger as an hclog.Logger so we don't run two
// log frameworks. Mapping is best-effort — Trace folds into Debug.
func hclogAdapter(l *slog.Logger) hclog.Logger {
	return hclog.New(&hclog.LoggerOptions{
		Name:   "raft",
		Output: hclogWriter{l: l},
		Level:  hclog.Info,
	})
}

// hclogWriter is the io.Writer hclog writes to. It forwards each line as a
// single Info-level slog message, which is good enough for raft's chatter.
type hclogWriter struct{ l *slog.Logger }

func (w hclogWriter) Write(p []byte) (int, error) {
	w.l.Info(string(p))
	return len(p), nil
}
