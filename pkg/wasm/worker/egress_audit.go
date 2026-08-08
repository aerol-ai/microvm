package worker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Worker subprocesses cannot call internal/service.emitEgressAudit, so they
// append compatible JSON Lines into the same secrets.jsonl the daemon reads
// ({Dir(SB_DB_PATH)}/audit/secrets.jsonl). O_APPEND keeps concurrent daemon
// + worker writers line-safe for small records.

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
		return
	}
	line = append(line, '\n')
	workerEgressAuditMu.Lock()
	defer workerEgressAuditMu.Unlock()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_, _ = f.Write(line)
	_ = f.Close()
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
