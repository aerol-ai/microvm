package cluster

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/raft"
	raftboltdb "github.com/hashicorp/raft-boltdb/v2"
	raftwal "github.com/hashicorp/raft-wal"
)

// raftTransportTimeout bounds each raft RPC's write and read, on both the
// TLS and the plain TCP transport. The pipeline stall guard derives its
// limit from it (raftPipelineStallFactor), so they move together.
const raftTransportTimeout = 10 * time.Second

const (
	raftLogBoltFilename = "raft-log.bolt"
	raftLogWALDirname   = "raft-wal"
	raftStableFilename  = "raft-stable.bolt"
)

// closableLogStore is raft.LogStore plus Close. raft.LogStore itself has no
// Close, but both BoltStore and raft-wal.WAL do — raftNode and recovery need
// a single type that covers both formats.
type closableLogStore interface {
	raft.LogStore
	io.Closer
}

// raftNode wraps the raft instance plus its on-disk stores so Close can shut
// them down in the right order.
type raftNode struct {
	raft      *raft.Raft
	transport *raft.NetworkTransport
	// pipelines is the transport raft was given: transport plus the stall
	// guard on replication pipelines (raft_pipeline_guard.go).
	pipelines *pipelineGuardTransport
	logStore  closableLogStore
	stableStr *raftboltdb.BoltStore
	snaps     raft.SnapshotStore
	logger    *slog.Logger
}

// raftSetupConfig captures the inputs setupRaft needs.
type raftSetupConfig struct {
	NodeID           string
	BindAddr         string // listen address for raft TCP transport
	AdvertiseAddr    string // address peers should reach us at
	DataDir          string // directory for log/stable/snapshot stores
	BootstrapCluster bool   // single-node bootstrap flag
	// TLS, when non-nil, switches the transport from plaintext TCP to mTLS via
	// a custom StreamLayer. Both peer connect AND peer accept require a cert
	// chained to the cluster CA — the same property the cluster-internal HTTP
	// listener uses. nil is reserved for isolated unit tests; cluster
	// configuration requires TLS.
	TLS *ClusterTLS
}

// testTuneRaft is set only by this package's TestMain, to shorten Raft's
// timers for in-process test clusters; it is nil in every binary. With raft's
// default 1 s heartbeat and election timeouts, each test cluster waited 1-2 s
// to elect a leader before its test could start: 133 tests took 1-2.5 s
// each, 254 s of the package's 623 s.
var testTuneRaft func(*raft.Config)

// Snapshot cadence. A snapshot copies every placement while Apply waits
// (raft calls Snapshot and Apply from one goroutine): 8.7 ms and 1.9 MiB at
// 10k placements, 100 ms and 19 MiB at 100k (BenchmarkFSMSnapshot, M1 Max,
// minimal specs; real specs are bigger). The cadence used to be 30 s / 1,024 entries "to keep the log
// small", but raft keeps TrailingLogs (10,240) entries after every snapshot
// anyway, so the log was never smaller: the stalls just came 4 to 8 times
// as often. These are the library's defaults, set here so a raft upgrade
// cannot move them unseen. A restart replays up to ~8k entries since the
// newest snapshot; an apply costs a few µs (BenchmarkFSMValidateHostPortAt10K:
// 2.9 µs), so that is tens of ms. recovery_store.go sizes the snapshot's blob
// fsyncs for SnapshotThreshold.
const (
	raftSnapshotInterval  = 120 * time.Second
	raftSnapshotThreshold = 8192
)

// newRaftConfig is the production raft config for nodeID.
func newRaftConfig(nodeID string, logger *slog.Logger) *raft.Config {
	rcfg := raft.DefaultConfig()
	rcfg.LocalID = raft.ServerID(nodeID)
	// Bridge raft's hclog to our slog. We accept some log-level lossiness in
	// exchange for not running two log destinations.
	rcfg.Logger = hclogAdapter(logger)
	rcfg.SnapshotInterval = raftSnapshotInterval
	rcfg.SnapshotThreshold = raftSnapshotThreshold
	return rcfg
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

	rcfg := newRaftConfig(cfg.NodeID, logger)
	if testTuneRaft != nil {
		testTuneRaft(rcfg)
	}

	// Format detection BEFORE recovery: if raft-log.bolt is present keep Bolt
	// (existing nodes); otherwise open raft-wal. Detection keys off the bolt
	// file existing — a bolt file is never byte-empty — not a fuzzy
	// "non-empty dir". Mixed-format clusters are safe (store is node-local).
	logStore, err := openRaftLogStore(cfg.DataDir, logger)
	if err != nil {
		return nil, err
	}
	stableStore, err := raftboltdb.NewBoltStore(filepath.Join(cfg.DataDir, raftStableFilename))
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
	var transport *raft.NetworkTransport
	if cfg.TLS != nil {
		// mTLS path: build a TLS StreamLayer ourselves and hand it to
		// NewNetworkTransport. raft.NewTCPTransport doesn't expose this seam,
		// which is why we duplicate the binding logic.
		stream, terr := newTLSStreamLayer(cfg.BindAddr, advertise, cfg.TLS.serverConfig(), cfg.TLS.clientConfig())
		if terr != nil {
			_ = logStore.Close()
			_ = stableStore.Close()
			return nil, fmt.Errorf("raft setup: tls transport on %q: %w", cfg.BindAddr, terr)
		}
		transport = raft.NewNetworkTransportWithConfig(&raft.NetworkTransportConfig{
			Stream:                stream,
			MaxPool:               3,
			Timeout:               raftTransportTimeout,
			Logger:                hclogAdapter(logger),
			ServerAddressProvider: nil,
		})
	} else {
		transport, err = raft.NewTCPTransportWithLogger(cfg.BindAddr, advertise, 3, raftTransportTimeout, hclogAdapter(logger))
		if err != nil {
			_ = logStore.Close()
			_ = stableStore.Close()
			return nil, fmt.Errorf("raft setup: tcp transport on %q: %w", cfg.BindAddr, err)
		}
	}

	if err := maybeRecoverRaftClusterFromPeersFile(cfg, rcfg, fsm, logStore, stableStore, snaps, transport, logger); err != nil {
		_ = transport.Close()
		_ = logStore.Close()
		_ = stableStore.Close()
		return nil, err
	}

	pipelines := newPipelineGuardTransport(transport, raftPipelineStallFactor*raftTransportTimeout, logger)
	r, err := raft.NewRaft(rcfg, fsm, logStore, stableStore, snaps, pipelines)
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
		pipelines: pipelines,
		logStore:  logStore,
		stableStr: stableStore,
		snaps:     snaps,
		logger:    logger,
	}, nil
}

// openRaftLogStore picks Bolt or WAL by on-disk format. Existing
// raft-log.bolt → Bolt (no conversion). Absent → WAL under raft-wal/.
// Reverting a WAL node is NOT in-place: drain → rejoin with bolt build +
// fresh DataDir (see setup/runbooks/lost-quorum-recovery.md).
func openRaftLogStore(dataDir string, logger *slog.Logger) (closableLogStore, error) {
	boltPath := filepath.Join(dataDir, raftLogBoltFilename)
	if st, err := os.Stat(boltPath); err == nil {
		if st.IsDir() {
			// A directory named raft-log.bolt is a corrupt layout, not a
			// signal to open WAL — BoltStore would also refuse it.
			return nil, fmt.Errorf("raft setup: bolt log store: %s is a directory", boltPath)
		}
		store, err := raftboltdb.NewBoltStore(boltPath)
		if err != nil {
			return nil, fmt.Errorf("raft setup: bolt log store: %w", err)
		}
		if logger != nil {
			logger.Info("raft log store: boltdb (existing raft-log.bolt)")
		}
		return store, nil
	} else if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("raft setup: stat log store: %w", err)
	}

	walDir := filepath.Join(dataDir, raftLogWALDirname)
	if err := os.MkdirAll(walDir, 0o700); err != nil {
		return nil, fmt.Errorf("raft setup: mkdir wal dir: %w", err)
	}
	store, err := raftwal.Open(walDir, raftwal.WithLogger(hclogAdapter(logger)))
	if err != nil {
		return nil, fmt.Errorf("raft setup: wal log store: %w", err)
	}
	if logger != nil {
		logger.Info("raft log store: raft-wal", "dir", walDir)
	}
	return store, nil
}

// detectRaftLogStoreFormat is the unit-test seam for format detection.
// Returns "bolt", "wal", or "" when dataDir is unusable.
func detectRaftLogStoreFormat(dataDir string) string {
	boltPath := filepath.Join(dataDir, raftLogBoltFilename)
	if st, err := os.Stat(boltPath); err == nil && !st.IsDir() {
		return "bolt"
	}
	return "wal"
}

func (r *raftNode) Close() error {
	// Order matters: shut raft first (it will stop using the transport and
	// stores), then close transport + stores.
	var firstErr error
	if r.raft != nil {
		var closePipelines func() int
		if r.pipelines != nil {
			closePipelines = r.pipelines.closePipelines
		}
		if err := awaitRaftShutdown(r.raft.Shutdown(), raftShutdownGrace, closePipelines, r.logger); err != nil {
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
