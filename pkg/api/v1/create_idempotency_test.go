package v1

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/models"
)

// createWithKey POSTs a create through the no-cluster handler, optionally
// carrying an Idempotency-Key, and returns the decoded response.
func createWithKey(t *testing.T, h *handlers, key string) (*models.CreateSandboxResponse, int) {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine:3.20"}`))
	if key != "" {
		req.Header.Set("Idempotency-Key", key)
	}
	h.createSandbox(rr, req)
	var resp models.CreateSandboxResponse
	if rr.Code == http.StatusCreated {
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode create response: %v; body=%s", err, rr.Body.String())
		}
	}
	return &resp, rr.Code
}

// A retried create carrying the same Idempotency-Key must replay the first
// sandbox rather than build a second one. On the pre-fix code createSandbox
// always minted a fresh id, so the second POST created a distinct sandbox —
// this test fails there (createCalls == 2, differing ids).
func TestCreateSandbox_IdempotencyKeyReplays(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))

	first, code := createWithKey(t, h, "key-abc")
	if code != http.StatusCreated {
		t.Fatalf("first create status = %d, want 201", code)
	}
	if rt.createCalls != 1 {
		t.Fatalf("after first create, createCalls = %d, want 1", rt.createCalls)
	}

	second, code := createWithKey(t, h, "key-abc")
	if code != http.StatusCreated {
		t.Fatalf("replay status = %d, want 201", code)
	}
	if rt.createCalls != 1 {
		t.Fatalf("after replay, createCalls = %d, want 1 (replay must not build a second sandbox)", rt.createCalls)
	}
	if first.ID == "" || second.ID != first.ID {
		t.Fatalf("replay id = %q, want the first id %q", second.ID, first.ID)
	}
}

// Two creates with different keys (or none) stay independent: the key is opt-in
// and does not collapse deliberately distinct creates.
func TestCreateSandbox_DistinctKeysAndNoKeyStayIndependent(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))

	a, _ := createWithKey(t, h, "k1")
	b, _ := createWithKey(t, h, "k2")
	if a.ID == b.ID {
		t.Fatalf("distinct keys produced the same id %q", a.ID)
	}

	// No key at all: every call mints a fresh sandbox (the default).
	c, _ := createWithKey(t, h, "")
	d, _ := createWithKey(t, h, "")
	if c.ID == d.ID {
		t.Fatalf("keyless creates produced the same id %q", c.ID)
	}
	if rt.createCalls != 4 {
		t.Fatalf("createCalls = %d, want 4 (k1, k2, and two keyless)", rt.createCalls)
	}
}

// The derived id must match clustercreate.DeterministicSandboxID for the
// create owner, so the handler and the cluster reservation agree on the id.
func TestCreateSandbox_DerivedIDShape(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, _ := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))

	resp, _ := createWithKey(t, h, "key-shape")
	if !strings.HasPrefix(resp.ID, "sb-") || len(resp.ID) != len("sb-")+16 {
		t.Fatalf("derived id = %q, want sb-<16 hex>", resp.ID)
	}
	if err := models.ValidateSandboxID(resp.ID); err != nil {
		t.Fatalf("derived id %q is not a valid sandbox id: %v", resp.ID, err)
	}
}

// On the cluster path an Idempotency-Key threads into the reserved id, so a
// retry reserves the same id (ErrReservationConflict then routes to the
// existing placement) instead of placing a second sandbox. Without the key the
// reserved id is freshly minted each call. On the pre-fix code clusterCreateWrap
// passed no PreferredSandboxID, so same-key reservations would differ — this
// test fails there.
func TestClusterCreateWrap_IdempotencyKeyFixesReservedID(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	fakeCluster := &createForwardCluster{
		Noop:   cluster.NewNoop("node-a", "http://node-a", ""),
		target: cluster.PlacementTarget{NodeID: "node-b", APIURL: "http://node-b:21212", IsSelf: false},
	}
	svc.AttachCluster(fakeCluster)
	h := &handlers{deps: Deps{Service: svc, Logger: logger}}

	post := func(key string) string {
		before := len(fakeCluster.reserveCalls)
		req := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(`{"image":"alpine"}`))
		if key != "" {
			req.Header.Set("Idempotency-Key", key)
		}
		rr := httptest.NewRecorder()
		h.clusterCreateWrap(rr, req)
		if rr.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202 (forwarded); body=%s", rr.Code, rr.Body.String())
		}
		if len(fakeCluster.reserveCalls) != before+1 {
			t.Fatalf("expected one new reservation for key %q", key)
		}
		return fakeCluster.reserveCalls[len(fakeCluster.reserveCalls)-1].sandboxID
	}

	withKey1 := post("key-xyz")
	withKey2 := post("key-xyz")
	if withKey1 == "" || withKey1 != withKey2 {
		t.Fatalf("same key reserved different ids %q vs %q", withKey1, withKey2)
	}
	if noKey := post(""); noKey == withKey1 {
		t.Fatalf("keyless create reused the keyed reservation id %q", noKey)
	}
}

// The local-image create path (createSandboxOnSelectedNode with no reservation)
// also honors the Idempotency-Key: a retry replays the existing sandbox through
// CreateSandboxWithID instead of building a second one.
func TestCreateSandboxOnSelectedNode_SelfLocalIdempotencyKeyReplays(t *testing.T) {
	rt := &apiRecordingRuntime{}
	stub := &promoteStubCluster{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	h, _ := newClusterCreateHarness(t, rt, stub)

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	call := func() *models.CreateSandboxResponse {
		rr := httptest.NewRecorder()
		httpReq := httptest.NewRequest(http.MethodPost, "/v1/sandboxes", nil)
		httpReq.Header.Set("Idempotency-Key", "local-key")
		h.createSandboxOnSelectedNode(rr, httpReq, req, "")
		if rr.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201; body=%s", rr.Code, rr.Body.String())
		}
		var resp models.CreateSandboxResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		return &resp
	}

	first := call()
	second := call()
	if rt.createCalls != 1 {
		t.Fatalf("createCalls = %d, want 1 (retry must replay, not rebuild)", rt.createCalls)
	}
	if first.ID == "" || second.ID != first.ID {
		t.Fatalf("replay id = %q, want first id %q", second.ID, first.ID)
	}
}
