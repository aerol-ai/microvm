package v1

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// POST /v1/sandboxes with an S3 mount on a node without mount-s3 (a local
// install skips the mount tools). The local-mode run on main f34b607e
// answered this 400, blaming the request; it is the node's configuration, so
// it is a 501 with a stable code, no Retry-After, and nothing is built.
// A mount the caller got wrong is still a 4xx on the same node.
func TestCreateSandboxMountToolUnavailableIs501(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // no mount-s3, or anything else, on this node
	rt := &apiRecordingRuntime{}
	h, st := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))

	rr := httptest.NewRecorder()
	h.createSandbox(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(
		`{"image":"alpine:3.20","mounts":[{"type":"s3","source":"s3://bucket","target":"/data"}]}`)))
	if rr.Code != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501; body=%s", rr.Code, rr.Body.String())
	}
	var resp models.ErrorResponse
	if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Code != models.ErrorCodeMountToolUnavailable || !strings.Contains(resp.Error, `"mount-s3": executable file not found`) {
		t.Fatalf("body = %s", rr.Body.String())
	}
	if rr.Header().Get("Retry-After") != "" {
		t.Fatal("a missing program is not retryable: no Retry-After")
	}
	if rt.createCalls != 0 {
		t.Fatalf("createCalls = %d, want 0", rt.createCalls)
	}
	if rows, _ := st.List(t.Context()); len(rows) != 0 {
		t.Fatalf("stored rows = %d, want 0", len(rows))
	}

	// Caller mistakes on the same node stay 4xx: they are rejected before
	// any mount tool runs.
	for _, body := range []string{
		`{"image":"alpine:3.20","mounts":[{"type":"s3","source":"s3://bucket","target":"/proc"}]}`,
		`{"image":"alpine:3.20","mounts":[{"type":"bogus","source":"x","target":"/data"}]}`,
		`{"image":"alpine:3.20","mounts":[{"type":"s3","source":"","target":"/data"}]}`,
	} {
		rr := httptest.NewRecorder()
		h.createSandbox(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(body)))
		if rr.Code < 400 || rr.Code >= 500 {
			t.Fatalf("%s: status = %d, want a 4xx; body=%s", body, rr.Code, rr.Body.String())
		}
	}
}
