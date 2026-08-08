package worker

import (
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// Worker subprocesses cannot call internal/service.emitEgressAudit. They append
// compatible JSON Lines into the same secrets.jsonl the daemon owns, under an
// exclusive flock shared with the daemon retention rewriter so an append
// cannot land on a soon-to-be-renamed inode and vanish silently.
// Full bounded-IPC into the authoritative queue remains follow-up (TODOS.md).

const workerEgressAuditFile = "secrets.jsonl"

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

var workerEgressAuditMu sync.Mutex

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
	m.SetEgressObserver(func(sandboxID, network, address string) {
		appendWorkerEgressAudit(path, node, sandboxID, network, address)
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
	line, err := json.Marshal(ev)
	if err != nil {
		slog.Warn("wasm egress audit marshal failed", "err", err)
		return
	}
	line = append(line, '\n')
	workerEgressAuditMu.Lock()
	defer workerEgressAuditMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		slog.Warn("wasm egress audit mkdir failed", "path", path, "err", err)
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		slog.Warn("wasm egress audit open failed", "path", path, "err", err)
		return
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		slog.Warn("wasm egress audit flock failed", "path", path, "err", err)
		return
	}
	defer func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN) }()
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
