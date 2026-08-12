package worker

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPostOrSpillWorkerEgressUsesIngest(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := strings.TrimPrefix(ln.Addr().String(), "127.0.0.1:")
	gotCh := make(chan map[string]string, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/audit/egress", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Aerol-Audit-Token") != "tok" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		raw, _ := io.ReadAll(r.Body)
		var m map[string]string
		_ = json.Unmarshal(raw, &m)
		gotCh <- m
		w.WriteHeader(http.StatusAccepted)
	})
	go http.Serve(ln, mux)

	postOrSpillWorkerEgress(egressAuditJob{
		port: port, token: "tok", node: "n1",
		sandboxID: "sb-1", network: "tcp", address: "example.com:443",
	})
	select {
	case m := <-gotCh:
		if m["sandbox_id"] != "sb-1" || m["destination"] != "example.com:443" || m["kind"] != "egress" {
			t.Fatalf("got %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ingest not called")
	}
}

func TestPostOrSpillWorkerEgressFallsBackToSpill(t *testing.T) {
	dir := t.TempDir()
	postOrSpillWorkerEgress(egressAuditJob{
		port: "1", token: "tok", spillDir: dir, node: "n1",
		sandboxID: "sb-1", network: "tcp", address: "host:9",
	})
	raw, err := os.ReadFile(filepath.Join(dir, workerEgressSpillFile))
	if err != nil {
		t.Fatal(err)
	}
	var ev workerEgressAuditEvent
	if err := json.Unmarshal(bytesTrimLine(raw), &ev); err != nil {
		t.Fatalf("unmarshal: %v raw=%s", err, raw)
	}
	if ev.Kind != "egress" || ev.SandboxID != "sb-1" || ev.Destination != "host:9" {
		t.Fatalf("spill event = %+v", ev)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("worker must not write secrets.jsonl, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "secrets.tip")); !os.IsNotExist(err) {
		t.Fatalf("worker must not write secrets.tip, err=%v", err)
	}
}

func TestInstallDefaultEgressObserverRespectsFlag(t *testing.T) {
	t.Setenv("SB_EGRESS_ATTRIBUTION_ENABLED", "false")
	t.Setenv("SB_DB_PATH", filepath.Join(t.TempDir(), "state.db"))
	t.Setenv("SB_AUDIT_INGEST_PORT", "21215")
	t.Setenv("SB_AUDIT_INGEST_TOKEN", "tok")
	m := newNetMediator()
	installDefaultEgressObserver(m)
	if m.egressObserver() != nil {
		t.Fatal("expected no observer when disabled")
	}

	t.Setenv("SB_EGRESS_ATTRIBUTION_ENABLED", "true")
	t.Setenv("SB_DB_PATH", "")
	t.Setenv("SB_AUDIT_INGEST_PORT", "")
	t.Setenv("SB_AUDIT_INGEST_TOKEN", "")
	m2 := newNetMediator()
	installDefaultEgressObserver(m2)
	if m2.egressObserver() != nil {
		t.Fatal("expected no observer without ingest or spill path")
	}

	dir := t.TempDir()
	dbPath := filepath.Join(dir, "state.db")
	t.Setenv("SB_DB_PATH", dbPath)
	t.Setenv("SB_NODE_ID", "n1")
	m3 := newNetMediator()
	installDefaultEgressObserver(m3)
	if m3.egressObserver() == nil {
		t.Fatal("expected observer when enabled + DB path (spill fallback)")
	}
	m3.egressObserver()("sb-x", "tcp", "host:9")
	deadline := time.Now().Add(2 * time.Second)
	path := filepath.Join(dir, "audit", workerEgressSpillFile)
	for {
		if _, err := os.Stat(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("spill file not written")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func bytesTrimLine(raw []byte) []byte {
	return []byte(strings.TrimSpace(string(raw)))
}
