package worker

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

func TestWorkerEgressAuditGapAndErrorHelpers(t *testing.T) {
	if err := errStatus(503); err == nil || err.Error() != "audit ingest status 503" {
		t.Fatalf("errStatus = %v", err)
	}

	before := workerEgressDropped.Load()
	empty, node := "", "n1"
	workerEgressGapDir.Store(&empty)
	workerEgressGapNode.Store(&node)
	workerEgressPendingGap.Store(0)
	noteWorkerEgressOverflow()
	if workerEgressDropped.Load() <= before {
		t.Fatal("overflow must count a drop even with no spill dir")
	}
	select {
	case <-workerEgressGapKick:
	default:
	}
	if flushWorkerEgressGap() {
		t.Fatal("no spill dir: flush must not claim a write")
	}
	appendWorkerEgressSpill("", workerEgressAuditEvent{SandboxID: "sb-1"})

	dir := t.TempDir()
	workerEgressGapDir.Store(&dir)
	noteWorkerEgressOverflow()
	select {
	case <-workerEgressGapKick:
	default:
	}
	flushWorkerEgressGap() // the pool goroutine may have flushed first
	spill := filepath.Join(dir, workerEgressSpillFile)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(spill); err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := os.Stat(spill); err != nil {
		t.Fatalf("gap spill missing: %v", err)
	}

	blocker := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	before = workerEgressDropped.Load()
	appendWorkerEgressSpill(filepath.Join(blocker, "nested"), workerEgressAuditEvent{SandboxID: "sb-2"})
	if workerEgressDropped.Load() <= before {
		t.Fatal("mkdir failure must count a drop")
	}

	postOrSpillWorkerEgress(egressAuditJob{})
	postOrSpillWorkerEgress(egressAuditJob{sandboxID: "sb", address: "host:1"})
	postOrSpillWorkerEgress(egressAuditJob{
		sandboxID: "sb", address: "host:1", eventTime: time.Time{},
	})

	t.Setenv("SB_EGRESS_ATTRIBUTION_ENABLED", "maybe")
	if !envBoolDefaultTrue("SB_EGRESS_ATTRIBUTION_ENABLED") {
		t.Fatal("invalid bool must default true")
	}
	t.Setenv("SB_EGRESS_ATTRIBUTION_ENABLED", "false")
	if envBoolDefaultTrue("SB_EGRESS_ATTRIBUTION_ENABLED") {
		t.Fatal("false must disable")
	}

	installDefaultEgressObserver(nil)
	t.Setenv("SB_EGRESS_ATTRIBUTION_ENABLED", "false")
	installDefaultEgressObserver(&NetMediator{})

	(*NetMediator)(nil).SetEgressObserver(nil)

	// Spill file is a directory so the append open fails.
	badSpill := t.TempDir()
	if err := os.Mkdir(filepath.Join(badSpill, workerEgressSpillFile), 0o700); err != nil {
		t.Fatal(err)
	}
	before = workerEgressDropped.Load()
	appendWorkerEgressSpill(badSpill, workerEgressAuditEvent{SandboxID: "sb-dir"})
	if workerEgressDropped.Load() <= before {
		t.Fatal("spill-as-directory must count a drop")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	port := strings.TrimPrefix(srv.URL, "http://127.0.0.1:")
	port = strings.TrimPrefix(port, "http://")
	if i := strings.LastIndex(port, ":"); i >= 0 {
		port = port[i+1:]
	}
	if err := postWorkerEgressAudit(egressAuditJob{port: port, capability: "cap", sandboxID: "sb", address: "h:1", network: "tcp"}); err == nil {
		t.Fatal("expected ingest status error")
	}
	postOrSpillWorkerEgress(egressAuditJob{port: port, capability: "cap", sandboxID: "sb", address: "h:1"})
}

func TestAuditBindingResolvers(t *testing.T) {
	s := &Server{}
	if _, ok := s.auditBinding("sb"); ok {
		t.Fatal("empty server had a binding")
	}
	s.setAuditBinding("sb", wasmengine.Capabilities{AuditCapability: "cap", AuditIncarnation: "inc"})
	if b, ok := s.auditBinding("sb"); !ok || b.capability != "cap" || b.incarnationID != "inc" {
		t.Fatalf("server binding = %+v %v", b, ok)
	}
	s.clearAuditBinding("sb")
	if _, ok := s.auditBinding("sb"); ok {
		t.Fatal("cleared server binding still present")
	}

	r := &ResidentServer{}
	if _, ok := r.auditBinding("sb"); ok {
		t.Fatal("empty resident had a binding")
	}
	r.setAuditBinding("sb", wasmengine.Capabilities{AuditCapability: "cap2", AuditIncarnation: "inc2"})
	if b, ok := r.auditBinding("sb"); !ok || b.capability != "cap2" {
		t.Fatalf("resident binding = %+v %v", b, ok)
	}
	r.clearAuditBinding("sb")
}
