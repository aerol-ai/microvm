package worker

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppendWorkerEgressAudit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit", "secrets.jsonl")
	appendWorkerEgressAudit(path, "node-w", "sb-1", "tcp", "example.com:443")
	appendWorkerEgressAudit(path, "node-w", "", "tcp", "skip") // empty sandbox — no-op
	appendWorkerEgressAudit("", "node-w", "sb-1", "tcp", "skip")

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var ev workerEgressAuditEvent
	if err := json.Unmarshal(raw[:len(raw)-1], &ev); err != nil {
		t.Fatalf("unmarshal: %v\nraw=%s", err, raw)
	}
	if ev.Kind != "egress" || ev.SandboxID != "sb-1" || ev.Destination != "example.com:443" ||
		ev.Network != "tcp" || ev.NodeID != "node-w" || ev.Result != "success" {
		t.Fatalf("event = %+v", ev)
	}
	if ev.Time.IsZero() || time.Since(ev.Time) > time.Minute {
		t.Fatalf("time = %v", ev.Time)
	}
}

func TestInstallDefaultEgressObserverRespectsFlag(t *testing.T) {
	t.Setenv("SB_EGRESS_ATTRIBUTION_ENABLED", "false")
	t.Setenv("SB_DB_PATH", filepath.Join(t.TempDir(), "state.db"))
	m := newNetMediator()
	installDefaultEgressObserver(m)
	if m.egressObserver() != nil {
		t.Fatal("expected no observer when disabled")
	}

	t.Setenv("SB_EGRESS_ATTRIBUTION_ENABLED", "true")
	t.Setenv("SB_DB_PATH", "")
	m2 := newNetMediator()
	installDefaultEgressObserver(m2)
	if m2.egressObserver() != nil {
		t.Fatal("expected no observer without SB_DB_PATH")
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	t.Setenv("SB_DB_PATH", dbPath)
	t.Setenv("SB_NODE_ID", "n1")
	m3 := newNetMediator()
	installDefaultEgressObserver(m3)
	if m3.egressObserver() == nil {
		t.Fatal("expected observer when enabled + DB path")
	}
	m3.egressObserver()("sb-x", "tcp", "host:9")
	deadline := time.Now().Add(2 * time.Second)
	path := filepath.Join(dir, "audit", "secrets.jsonl")
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("audit file not written")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
