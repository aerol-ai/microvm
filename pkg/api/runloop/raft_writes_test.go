package runloop

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// specWriteCounter stands in for the cluster and counts UpsertSpec calls and
// SpecOf reads. In a real cluster each UpsertSpec is a Raft log entry
// (opUpsertSpec) that every server fsyncs, and on a worker each SpecOf is a
// round trip to the servers. It embeds cluster.Noop so the devbox stays
// owned by this node.
type specWriteCounter struct {
	*cluster.Noop

	mu     sync.Mutex
	spec   models.CreateSandboxRequest
	writes int
	reads  int
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

// TestRunloopRoutesRaftWrites pins how many replicated-spec writes (Raft
// entries) and spec reads Runloop's keep-alive and update routes make.
// keep_alive only bumps the local idle clock (TouchSandbox), so it never
// reaches Raft. Metadata (native tags) and the name (compat blob) are
// replicated only for a failover=recreate devbox, and a repeat of the same
// value writes nothing.
func TestRunloopRoutesRaftWrites(t *testing.T) {
	type step struct {
		name   string
		path   string
		body   any
		writes [2]int // Raft spec writes this step adds: {default, failover=recreate}
	}
	steps := []step{
		{"keep_alive", "/keep_alive", nil, [2]int{0, 0}},
		{"keep_alive again", "/keep_alive", nil, [2]int{0, 0}},
		{"set metadata", "", map[string]any{"metadata": map[string]string{"team": "a"}}, [2]int{0, 1}},
		{"same metadata again", "", map[string]any{"metadata": map[string]string{"team": "a"}}, [2]int{0, 0}},
		{"rename", "", map[string]any{"name": "renamed"}, [2]int{0, 1}},
		{"same name again", "", map[string]any{"name": "renamed"}, [2]int{0, 0}},
		// Tags and the blob are separate service writes, so one call that
		// changes both makes two entries.
		{"metadata and name together", "", map[string]any{"metadata": map[string]string{"team": "b"}, "name": "renamed-2"}, [2]int{0, 2}},
	}
	for policy, label := range []string{"default devbox", "failover=recreate devbox"} {
		t.Run(label, func(t *testing.T) {
			env := newTestEnv(t)
			view := env.mustCreate(t, map[string]any{"blueprint_name": "python"})
			if policy == 1 {
				execSQL(t, env.store, "UPDATE sandboxes SET failover_policy = 'recreate' WHERE id = '"+view.ID+"'")
			}
			counter := &specWriteCounter{Noop: cluster.NewNoop("self", "http://self", ""), spec: models.CreateSandboxRequest{Image: "python:3.12"}}
			env.svc.AttachCluster(counter)

			for _, s := range steps {
				writesBefore, readsBefore := counter.counts()
				rr := env.do(t, http.MethodPost, "/"+view.ID+s.path, s.body, nil)
				if rr.Code != http.StatusOK {
					t.Fatalf("%s: status = %d, want 200; body=%s", s.name, rr.Code, rr.Body.String())
				}
				writes, reads := counter.counts()
				if got := writes - writesBefore; got != s.writes[policy] {
					t.Errorf("%s: Raft spec writes = %d, want %d", s.name, got, s.writes[policy])
				}
				if policy == 0 && reads != readsBefore {
					t.Errorf("%s: spec reads (server round trips) = %d, want 0", s.name, reads-readsBefore)
				}
			}
		})
	}
}
