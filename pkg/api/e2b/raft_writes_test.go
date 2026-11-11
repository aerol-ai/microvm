package e2b

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// specWriteCounter stands in for the cluster and counts UpsertSpec calls. In a
// real cluster each one is a Raft log entry (opUpsertSpec) that every server
// fsyncs, so this count is the facade's Raft cost per call. It embeds
// cluster.Noop so the sandbox stays owned by this node.
type specWriteCounter struct {
	*cluster.Noop

	mu     sync.Mutex
	spec   models.CreateSandboxRequest
	writes int
}

func newSpecWriteCounter(spec models.CreateSandboxRequest) *specWriteCounter {
	return &specWriteCounter{Noop: cluster.NewNoop("self", "http://self", ""), spec: spec}
}

func (c *specWriteCounter) SpecOf(string) *models.CreateSandboxRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	cp := c.spec
	return &cp
}

func (c *specWriteCounter) UpsertSpec(_ context.Context, _ string, spec *models.CreateSandboxRequest, _ cluster.PlacementSecrets) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.spec = *spec
	c.writes++
	return nil
}

func (c *specWriteCounter) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes
}

// TestE2BTimeoutRoutesRaftWrites pins how many replicated-spec writes (Raft
// entries) E2B's timeout and connect routes make. Both used to re-save the E2B
// compat blob after changing the lifecycle. The blob holds no timeout, so that
// save wrote the same bytes, and since B11 every compat-state save also goes
// to Raft: two Raft writes per setTimeout where the native lifecycle update
// makes one.
func TestE2BTimeoutRoutesRaftWrites(t *testing.T) {
	ctx := context.Background()
	svc, st, handler := newE2BHandlerTestEnv(t)

	createResp := httptest.NewRecorder()
	handler.ServeHTTP(createResp, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes",
		strings.NewReader(`{"templateID":"base","timeout":120,"autoPause":true}`)))
	if createResp.Code != http.StatusCreated {
		t.Fatalf("create status = %d; body=%s", createResp.Code, createResp.Body.String())
	}
	var created sandboxResponse
	if err := json.NewDecoder(createResp.Body).Decode(&created); err != nil {
		t.Fatalf("decode create: %v", err)
	}
	id := created.SandboxID

	blobBefore, err := st.GetCompatState(ctx, id, models.FacadeE2B)
	if err != nil {
		t.Fatalf("GetCompatState before: %v", err)
	}

	// Attach the counter after the create, so only the calls below count.
	counter := newSpecWriteCounter(models.CreateSandboxRequest{Image: "ubuntu:22.04"})
	svc.AttachCluster(counter)

	steps := []struct {
		name       string
		path       string
		body       string
		wantStatus int
		wantWrites int // replicated-spec writes this step adds
	}{
		{"setTimeout", "/timeout", `{"timeout":300}`, http.StatusNoContent, 1},
		{"setTimeout again, same value", "/timeout", `{"timeout":300}`, http.StatusNoContent, 1},
		{"connect that extends the timeout", "/connect", `{"timeout":3600}`, http.StatusOK, 1},
		{"connect that does not extend it", "/connect", `{"timeout":1}`, http.StatusOK, 0},
	}
	for _, step := range steps {
		before := counter.count()
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+step.path, strings.NewReader(step.body)))
		if resp.Code != step.wantStatus {
			t.Fatalf("%s: status = %d, want %d; body=%s", step.name, resp.Code, step.wantStatus, resp.Body.String())
		}
		if got := counter.count() - before; got != step.wantWrites {
			t.Errorf("%s: Raft spec writes = %d, want %d", step.name, got, step.wantWrites)
		}
	}

	// The E2B blob is untouched: the timeout is read from the native lifecycle.
	blobAfter, err := st.GetCompatState(ctx, id, models.FacadeE2B)
	if err != nil {
		t.Fatalf("GetCompatState after: %v", err)
	}
	if blobAfter.StateJSON != blobBefore.StateJSON {
		t.Errorf("E2B compat blob changed:\nbefore %s\nafter  %s", blobBefore.StateJSON, blobAfter.StateJSON)
	}
	meta, err := loadE2BSandboxMeta(ctx, st, id)
	if err != nil {
		t.Fatalf("loadE2BSandboxMeta: %v", err)
	}
	if meta.TimeoutSeconds != 3600 {
		t.Errorf("TimeoutSeconds = %d, want 3600 (from the native lifecycle)", meta.TimeoutSeconds)
	}
	if meta.OnTimeout != "pause" {
		t.Errorf("OnTimeout = %q, want pause (kept in the blob)", meta.OnTimeout)
	}
}
