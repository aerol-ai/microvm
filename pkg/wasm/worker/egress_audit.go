package worker

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

// Worker subprocesses cannot call internal/service.emitEgressAudit. They append
// compatible JSON Lines into the same secrets.jsonl the daemon owns, under an
// exclusive flock on a stable sidecar lock file acquired *before* opening the
// data file so retention rename cannot leave writers on an unlinked inode.
// Full bounded-IPC into the authoritative queue remains follow-up (TODOS.md).

const (
	workerEgressAuditFile = "secrets.jsonl"
	workerEgressLockFile  = "secrets.jsonl.lock"
	workerEgressWorkers   = 8
	workerEgressQueue     = 1024
)

type workerEgressAuditEvent struct {
	Time        time.Time `json:"time"`
	Actor       string    `json:"actor,omitempty"`
	SandboxID   string    `json:"sandbox_id,omitempty"`
	Result      string    `json:"result"`
	Reason      string    `json:"reason,omitempty"`
	NodeID      string    `json:"node_id,omitempty"`
	Kind        string    `json:"kind,omitempty"`
	Destination string    `json:"destination,omitempty"`
	Network     string    `json:"network,omitempty"`
}

type egressAuditJob struct {
	path, node, sandboxID, network, address string
}

var (
	workerEgressOnce    sync.Once
	workerEgressCh      chan egressAuditJob
	workerEgressDropped atomic.Int64
)

// installDefaultEgressObserver wires destination attribution when
// SB_EGRESS_ATTRIBUTION_ENABLED is unset/true and SB_DB_PATH is set (inherited
// from the parent daemon). No-op when disabled or path unknown.
func installDefaultEgressObserver(m *NetMediator) {
	if m == nil || !envBoolDefaultTrue("SB_EGRESS_ATTRIBUTION_ENABLED") {
		return
	}
	path, node := workerEgressAuditTarget()
	if path == "" {
		return
	}
	ensureWorkerEgressPool()
	m.SetEgressObserver(func(sandboxID, network, address string) {
		job := egressAuditJob{path: path, node: node, sandboxID: sandboxID, network: network, address: address}
		select {
		case workerEgressCh <- job:
		default:
			workerEgressDropped.Add(1)
			slog.Warn("wasm egress audit queue full; writing gap marker",
				"sandbox_id", sandboxID, "destination", address, "dropped_total", workerEgressDropped.Load())
			appendWorkerEgressGap(path, node, sandboxID)
		}
	})
}

func ensureWorkerEgressPool() {
	workerEgressOnce.Do(func() {
		workerEgressCh = make(chan egressAuditJob, workerEgressQueue)
		for i := 0; i < workerEgressWorkers; i++ {
			go func() {
				for job := range workerEgressCh {
					appendWorkerEgressAudit(job.path, job.node, job.sandboxID, job.network, job.address)
				}
			}()
		}
	})
}

func workerEgressAuditTarget() (path, node string) {
	dbPath := strings.TrimSpace(os.Getenv("SB_DB_PATH"))
	if dbPath == "" {
		return "", ""
	}
	return filepath.Join(filepath.Dir(dbPath), "audit", workerEgressAuditFile), strings.TrimSpace(os.Getenv("SB_NODE_ID"))
}

func appendWorkerEgressAudit(path, node, sandboxID, network, address string) {
	sandboxID = strings.TrimSpace(sandboxID)
	address = strings.TrimSpace(address)
	if path == "" || sandboxID == "" || address == "" {
		return
	}
	ev := workerEgressAuditEvent{
		Time:        time.Now().UTC(),
		Actor:       node,
		SandboxID:   sandboxID,
		Result:      "success",
		Reason:      "ok",
		NodeID:      node,
		Kind:        "egress",
		Destination: address,
		Network:     strings.TrimSpace(network),
	}
	appendWorkerEgressEvent(path, ev)
}

func appendWorkerEgressGap(path, node, sandboxID string) {
	if path == "" {
		return
	}
	appendWorkerEgressEvent(path, workerEgressAuditEvent{
		Time:      time.Now().UTC(),
		Actor:     node,
		SandboxID: strings.TrimSpace(sandboxID),
		Result:    "gap",
		Reason:    "overflow",
		NodeID:    node,
		Kind:      "gap",
	})
}

func appendWorkerEgressEvent(path string, ev workerEgressAuditEvent) {
	line, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("wasm egress audit marshal failed", "err", err)
		return
	}
	line = append(line, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		slog.Warn("wasm egress audit mkdir failed", "path", path, "err", err)
		return
	}
	lockPath := filepath.Join(dir, workerEgressLockFile)
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		slog.Warn("wasm egress audit lock open failed", "path", lockPath, "err", err)
		return
	}
	defer lf.Close()
	if err := unix.Flock(int(lf.Fd()), unix.LOCK_EX); err != nil {
		slog.Warn("wasm egress audit flock failed", "path", lockPath, "err", err)
		return
	}
	defer func() { _ = unix.Flock(int(lf.Fd()), unix.LOCK_UN) }()

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Warn("wasm egress audit open failed", "path", path, "err", err)
		return
	}
	defer f.Close()
	if _, err := f.Write(line); err != nil {
		slog.Warn("wasm egress audit write failed", "path", path, "err", err)
	}
}

func envBoolDefaultTrue(key string) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return true
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return true
	}
	return b
}
