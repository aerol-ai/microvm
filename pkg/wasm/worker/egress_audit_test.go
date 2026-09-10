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
		if r.Header.Get("X-Aerol-Audit-Capability") != "cap" {
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
		port: port, capability: "cap", node: "n1",
		sandboxID: "sb-1", network: "tcp", address: "example.com:443",
		eventTime: time.Now().UTC(),
	})
	select {
	case m := <-gotCh:
		if m["destination"] != "example.com:443" || m["kind"] != "" || m["sandbox_id"] != "" {
			t.Fatalf("got %+v", m)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ingest not called")
	}
}

func TestPostOrSpillWorkerEgressFallsBackToSpill(t *testing.T) {
	dir := t.TempDir()
	postOrSpillWorkerEgress(egressAuditJob{
		port: "1", capability: "cap", spillDir: dir, node: "n1",
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
	t.Setenv("SB_AUDIT_SPILL_DIR", filepath.Join(t.TempDir(), "audit"))
	t.Setenv("SB_AUDIT_INGEST_PORT", "21215")
	t.Setenv("SB_AUDIT_INGEST_TOKEN", "tok")
	m := newNetMediator()
	installDefaultEgressObserver(m)
	if m.egressObserver() != nil {
		t.Fatal("expected no observer when disabled")
	}

	t.Setenv("SB_EGRESS_ATTRIBUTION_ENABLED", "true")
	t.Setenv("SB_AUDIT_SPILL_DIR", "")
	t.Setenv("SB_AUDIT_INGEST_PORT", "")
	t.Setenv("SB_AUDIT_INGEST_TOKEN", "")
	m2 := newNetMediator()
	installDefaultEgressObserver(m2)
	if m2.egressObserver() != nil {
		t.Fatal("expected no observer without ingest or spill path")
	}

	dir := t.TempDir()
	t.Setenv("SB_AUDIT_SPILL_DIR", filepath.Join(dir, "audit"))
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

func TestInstalledObserverSpillsWhenConfiguredIngestFails(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "audit")
	t.Setenv("SB_EGRESS_ATTRIBUTION_ENABLED", "true")
	t.Setenv("SB_AUDIT_INGEST_PORT", "1")
	t.Setenv("SB_AUDIT_SPILL_DIR", dir)
	t.Setenv("SB_NODE_ID", "node-a")

	m := newNetMediator()
	installDefaultEgressObserver(m, func(sandboxID string) (egressAuditBinding, bool) {
		return egressAuditBinding{capability: "cap", incarnationID: "inc-1"}, sandboxID == "sb-fallback"
	})
	observer := m.egressObserver()
	if observer == nil {
		t.Fatal("expected egress observer")
	}
	observer("sb-fallback", "tcp", "example.com:443")

	path := filepath.Join(dir, workerEgressSpillFile)
	deadline := time.Now().Add(3 * time.Second)
	for {
		raw, err := os.ReadFile(path)
		if err == nil {
			var ev workerEgressAuditEvent
			if err := json.Unmarshal(bytesTrimLine(raw), &ev); err != nil {
				t.Fatalf("unmarshal spill: %v", err)
			}
			if ev.SandboxID != "sb-fallback" || ev.IncarnationID != "inc-1" || ev.Destination != "example.com:443" {
				t.Fatalf("spill event = %+v", ev)
			}
			break
		}
		if !os.IsNotExist(err) {
			t.Fatalf("read spill: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("spill file not written after ingest failure")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func bytesTrimLine(raw []byte) []byte {
	return []byte(strings.TrimSpace(string(raw)))
}

// The dial-path overflow branch must do no I/O: no directory, file, lock, or
// fsync — only counters. The writer later turns the count into ONE marker.
func TestObserverOverflowDoesNoIOOnDialPath(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "spill-not-created")
	node := "n-ovf"
	workerEgressGapDir.Store(&dir)
	workerEgressGapNode.Store(&node)
	workerEgressPendingGap.Store(0)
	before := workerEgressDropped.Load()

	// Overflow itself is two atomics: the counters move, the filesystem does
	// not. (The pool's flush goroutine may already be running from another
	// test and race us for the kick, so the marker may land before or after
	// our explicit flush; only the total is asserted.)
	stat := func() error { _, err := os.Stat(dir); return err }
	for range 37 {
		if err := stat(); !os.IsNotExist(err) {
			t.Fatalf("overflow touched the filesystem on the dial path (stat err=%v)", err)
		}
		noteWorkerEgressOverflow()
	}
	if got := workerEgressDropped.Load() - before; got != 37 {
		t.Fatalf("dropped counter delta = %d, want 37", got)
	}
	select {
	case <-workerEgressGapKick:
	default:
	}
	flushWorkerEgressGap()
	var total float64
	deadline := time.Now().Add(2 * time.Second)
	for {
		total = 0
		raw, err := os.ReadFile(filepath.Join(dir, workerEgressSpillFile))
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
				var ev map[string]any
				if err := json.Unmarshal([]byte(line), &ev); err != nil {
					t.Fatal(err)
				}
				if ev["kind"] != "gap" || ev["reason"] != "overflow" || ev["node_id"] != "n-ovf" {
					t.Fatalf("marker = %v", ev)
				}
				total += ev["dropped"].(float64)
			}
		}
		if total == 37 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if total != 37 {
		t.Fatalf("coalesced markers account for %v drops, want 37", total)
	}
	if flushWorkerEgressGap() {
		t.Fatal("nothing pending: flush must not write")
	}
	// Without a spill directory the counter is the only evidence; no panic,
	// no write.
	empty := ""
	workerEgressGapDir.Store(&empty)
	noteWorkerEgressOverflow()
	select {
	case <-workerEgressGapKick:
	default:
	}
	if flushWorkerEgressGap() {
		t.Fatal("flush without a spill dir must not claim to have written")
	}
}
