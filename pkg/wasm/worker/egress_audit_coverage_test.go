package worker

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWorkerEgressAuditGapAndErrorHelpers(t *testing.T) {
	if err := errStatus(503); err == nil || err.Error() != "audit ingest status 503" {
		t.Fatalf("errStatus = %v", err)
	}

	// A nil spill writer counts every loss and never touches a disk.
	var none *workerEgressSpiller
	before := workerEgressDropped.Load()
	none.enqueue(workerEgressAuditEvent{SandboxID: "sb-1"})
	none.noteDrop(2)
	if workerEgressDropped.Load() != before+3 {
		t.Fatalf("nil writer dropped delta = %d, want 3", workerEgressDropped.Load()-before)
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
