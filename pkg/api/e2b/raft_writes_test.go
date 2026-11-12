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

// specWriteCounter stands in for the cluster and counts UpsertSpec calls and
// SpecOf reads. In a real cluster each UpsertSpec is a Raft log entry
// (opUpsertSpec) that every server fsyncs, and on a worker each SpecOf is a
// round trip to the servers, so these counts are the facade's Raft cost per
// call. It embeds cluster.Noop so the sandbox stays owned by this node.
type specWriteCounter struct {
	*cluster.Noop

	mu     sync.Mutex
	spec   models.CreateSandboxRequest
	writes int
	reads  int
}

func newSpecWriteCounter(spec models.CreateSandboxRequest) *specWriteCounter {
	return &specWriteCounter{Noop: cluster.NewNoop("self", "http://self", ""), spec: spec}
}

func (c *specWriteCounter) SpecOf(string) *models.CreateSandboxRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.reads++
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

func (c *specWriteCounter) counts() (writes, reads int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.writes, c.reads
}

// TestE2BTimeoutRoutesRaftWrites pins how many replicated-spec writes (Raft
// entries) and spec reads (server round trips) E2B's timeout and connect
// routes make.
//
//   - Both routes used to re-save the E2B compat blob after changing the
//     lifecycle. The blob holds no timeout, so that save wrote the same bytes,
//     and since B11 every compat-state save also went to Raft.
//   - The lifecycle itself is replicated only for a sandbox with
//     failover=recreate, the one case that reads it back. A default sandbox's
//     keep-alive costs nothing on the servers.
//   - The timeout is stored as an age (elapsed time plus the new timeout), so
//     each setTimeout moves it later. On a failover sandbox the replicated
//     copy may lag by up to a minute (replicateRecoveryLifecycle): a repeat
//     within the minute writes nothing, a jump of more than a minute writes.
func TestE2BTimeoutRoutesRaftWrites(t *testing.T) {
	type step struct {
		name       string
		path       string
		body       string
		wantStatus int
		wantWrites int // replicated-spec writes this step adds
		wantReads  int // spec reads this step adds; -1: not asserted
	}
	cases := []struct {
		name     string
		recreate bool
		steps    []step
	}{
		{"default sandbox", false, []step{
			{"setTimeout", "/timeout", `{"timeout":300}`, http.StatusNoContent, 0, 0},
			{"setTimeout again, same value", "/timeout", `{"timeout":300}`, http.StatusNoContent, 0, 0},
			{"connect that extends the timeout", "/connect", `{"timeout":3600}`, http.StatusOK, 0, 0},
			{"connect that does not extend it", "/connect", `{"timeout":1}`, http.StatusOK, 0, 0},
		}},
		{"failover=recreate sandbox", true, []step{
			{"setTimeout", "/timeout", `{"timeout":300}`, http.StatusNoContent, 1, -1},
			{"setTimeout again, same value", "/timeout", `{"timeout":300}`, http.StatusNoContent, 0, -1},
			{"connect that extends the timeout", "/connect", `{"timeout":3600}`, http.StatusOK, 1, -1},
			{"connect that does not extend it", "/connect", `{"timeout":1}`, http.StatusOK, 0, 0},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
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
			if tc.recreate {
				// E2B's create has no failover field; the policy comes from
				// /v1 or a facade default. Set it on the row directly.
				execStoreSQL(t, st, "UPDATE sandboxes SET failover_policy = 'recreate' WHERE id = '"+id+"'")
			}

			blobBefore, err := st.GetCompatState(ctx, id, models.FacadeE2B)
			if err != nil {
				t.Fatalf("GetCompatState before: %v", err)
			}

			// Attach the counter after the create, so only the calls below count.
			counter := newSpecWriteCounter(models.CreateSandboxRequest{Image: "ubuntu:22.04"})
			svc.AttachCluster(counter)

			for _, s := range tc.steps {
				writesBefore, readsBefore := counter.counts()
				resp := httptest.NewRecorder()
				handler.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/e2b/sandboxes/"+id+s.path, strings.NewReader(s.body)))
				if resp.Code != s.wantStatus {
					t.Fatalf("%s: status = %d, want %d; body=%s", s.name, resp.Code, s.wantStatus, resp.Body.String())
				}
				writes, reads := counter.counts()
				if got := writes - writesBefore; got != s.wantWrites {
					t.Errorf("%s: Raft spec writes = %d, want %d", s.name, got, s.wantWrites)
				}
				if got := reads - readsBefore; s.wantReads >= 0 && got != s.wantReads {
					t.Errorf("%s: spec reads (server round trips) = %d, want %d", s.name, got, s.wantReads)
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
		})
	}
}
