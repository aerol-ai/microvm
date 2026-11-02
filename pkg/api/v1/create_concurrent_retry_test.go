package v1

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/api/clustercreate"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The reported bug, end to end on one node: SDK retries of one keyed
// POST /v1/sandboxes arrive while the first create still runs. Each used to
// run its own create, fail on the container name with 409, and release the
// first create's capacity reservation (GET /v1/capacity showed cpu=0 mem=0
// active=0 with the sandbox running). Now they wait and replay it: every
// answer is 201 naming the one sandbox, and the capacity view holds exactly
// one sandbox's reservation throughout.
func TestCreateSandbox_ConcurrentKeyedRetriesReplay(t *testing.T) {
	const body = `{"image":"alpine:3.20","cpu":2,"memory_mb":1024}`
	rt := &apiRecordingRuntime{gate: newCreateGate()}
	h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))
	post := func() *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(body))
		req.Header.Set("Idempotency-Key", "job-500")
		h.clusterCreateWrap(rr, req)
		return rr
	}
	capacityView := func() capacity.Snapshot {
		rr := httptest.NewRecorder()
		h.capacity(rr, httptest.NewRequest(http.MethodGet, "/v1/capacity", nil))
		var snap capacity.Snapshot
		if err := json.Unmarshal(rr.Body.Bytes(), &snap); err != nil {
			t.Fatalf("capacity: %v", err)
		}
		return snap
	}
	assertOne := func(when string) {
		t.Helper()
		snap := capacityView()
		if snap.SandboxesActive != 1 || snap.ReservedCPU != 2 || snap.ReservedMemoryMB != 1024 {
			t.Fatalf("%s: capacity active=%d cpu=%v mem=%d, want one sandbox at cpu=2 mem=1024", when, snap.SandboxesActive, snap.ReservedCPU, snap.ReservedMemoryMB)
		}
	}

	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- post() }()
	<-rt.gate.entered
	assertOne("first create running")

	const retries = 5
	retried := make(chan *httptest.ResponseRecorder, retries)
	for range retries {
		go func() { retried <- post() }()
	}
	time.Sleep(50 * time.Millisecond)
	if n := rt.gate.creates(); n != 1 {
		t.Fatalf("runtime creates while the first runs = %d, want 1", n)
	}
	assertOne("retries waiting")
	close(rt.gate.hold)

	rr := <-first
	if rr.Code != http.StatusCreated {
		t.Fatalf("first create = %d %s", rr.Code, rr.Body.String())
	}
	id := createdID(t, rr)
	for range retries {
		rr := <-retried
		if rr.Code != http.StatusCreated || createdID(t, rr) != id {
			t.Fatalf("retry = %d %s; want 201 naming %s", rr.Code, rr.Body.String(), id)
		}
	}
	if n := rt.gate.creates(); n != 1 {
		t.Fatalf("runtime creates = %d, want exactly 1", n)
	}
	assertOne("after every retry")
	if _, err := h.deps.Service.GetSandbox(t.Context(), id); err != nil {
		t.Fatalf("the sandbox is gone: %v", err)
	}
}

// A reserved create whose reservation is gone (a retry that waited out a
// failed create of its id) answers 503 with Retry-After, so the SDK retries
// and reserves afresh; any other seal failure stays a 500.
func TestWriteOverlapCreateErrorReservationGone(t *testing.T) {
	h := &handlers{deps: Deps{Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}
	tests := []struct {
		name       string
		err        error
		wantStatus int
		wantRetry  string
	}{
		{name: "reservation gone", err: &clustercreate.OverlapFailure{Phase: clustercreate.OverlapPhaseSeal, Err: service.ErrReservedPlacementGone}, wantStatus: http.StatusServiceUnavailable, wantRetry: "1"},
		{name: "reservation another node's", err: &clustercreate.OverlapFailure{Phase: clustercreate.OverlapPhaseSeal, Err: fmt.Errorf("%w: not owned by this node", service.ErrReservedPlacementGone)}, wantStatus: http.StatusServiceUnavailable, wantRetry: "1"},
		{name: "other seal failure", err: &clustercreate.OverlapFailure{Phase: clustercreate.OverlapPhaseSeal, Err: errors.New("key store down")}, wantStatus: http.StatusInternalServerError},
		{name: "create still running past the wait", err: service.ErrCreateInProgress, wantStatus: http.StatusServiceUnavailable, wantRetry: "5"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			h.writeOverlapCreateError(rr, tt.err)
			if rr.Code != tt.wantStatus || rr.Header().Get("Retry-After") != tt.wantRetry {
				t.Fatalf("status %d Retry-After %q, want %d %q (%s)", rr.Code, rr.Header().Get("Retry-After"), tt.wantStatus, tt.wantRetry, rr.Body.String())
			}
		})
	}
}

// The local-image (unreserved) cluster create keys its retries too: a retry
// replays the sandbox without sealing or promoting it again, and a different
// request under the key is refused before anything runs.
func TestCreateSandboxOnSelectedNode_LocalKeyedReplay(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, _ := newClusterCreateHarness(t, rt, stub)
	create := func(digest string) *httptest.ResponseRecorder {
		rr := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		r.Header.Set("Idempotency-Key", "job-501")
		r = withIdempotencyKey(r)
		h.createSandboxOnSelectedNode(rr, r, models.CreateSandboxRequest{Image: "alpine:3.20", CreateRequestDigests: []string{digest}}, "")
		return rr
	}
	first := create("hmac:0:aaaa")
	if first.Code != http.StatusCreated {
		t.Fatalf("first = %d %s", first.Code, first.Body.String())
	}
	id := createdID(t, first)
	if len(stub.recordCalls) != 1 {
		t.Fatalf("promotes = %d, want 1", len(stub.recordCalls))
	}
	again := create("hmac:0:aaaa")
	if again.Code != http.StatusCreated || createdID(t, again) != id {
		t.Fatalf("retry = %d %s, want a replay of %s", again.Code, again.Body.String(), id)
	}
	if len(stub.recordCalls) != 1 || rt.createCalls != 1 || len(stub.deleteCalls) != 0 {
		t.Fatalf("the replay promoted %d, created %d, deleted %d; want 1, 1, 0", len(stub.recordCalls), rt.createCalls, len(stub.deleteCalls))
	}
	assertKeyReused(t, create("hmac:0:bbbb"), "job-501")
}
