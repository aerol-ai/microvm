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

// POST /v1/sandboxes with a mount-tool flag off the allow list is the
// caller's mistake: 400, the error names the flag, and nothing is built.
func TestCreateSandboxMountToolOptionOffAllowListIs400(t *testing.T) {
	rt := &apiRecordingRuntime{}
	h, st := newClusterCreateHarness(t, rt, cluster.NewNoop("node-a", "http://node-a", ""))

	cases := []struct {
		body string
		want string
	}{
		{
			`{"image":"alpine:3.20","mounts":[{"type":"s3","source":"s3://bucket","target":"/data","options":{"extra_args":"--cache /var/lib"}}]}`,
			`mount 0: options.extra_args flag "--cache" is not allowed`,
		},
		{
			`{"image":"alpine:3.20","mounts":[{"type":"nfs","source":"h:/e","target":"/data","options":{"opts":"rw,suid"}}]}`,
			`mount 0: options.opts entry "suid" is not allowed`,
		},
	}
	for _, tc := range cases {
		rr := httptest.NewRecorder()
		h.createSandbox(rr, httptest.NewRequest(http.MethodPost, "/v1/sandboxes", strings.NewReader(tc.body)))
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400; body=%s", rr.Code, rr.Body.String())
		}
		var resp models.ErrorResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(resp.Error, tc.want) {
			t.Fatalf("error = %q, want it to contain %q", resp.Error, tc.want)
		}
	}
	if rt.createCalls != 0 {
		t.Fatalf("createCalls = %d, want 0", rt.createCalls)
	}
	if rows, _ := st.List(t.Context()); len(rows) != 0 {
		t.Fatalf("stored rows = %d, want 0", len(rows))
	}
}
