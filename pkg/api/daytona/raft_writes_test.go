package daytona

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// specWriteCounter stands in for the cluster and counts UpsertSpec calls and
// SpecOf reads. In a real cluster each UpsertSpec is a Raft log entry
// (opUpsertSpec) that every server fsyncs, and on a worker each SpecOf is a
// round trip to the servers. It embeds cluster.Noop so the sandbox stays
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

// TestDaytonaRoutesRaftWrites pins how many replicated-spec writes (Raft
// entries) and spec reads Daytona's settings routes make. Each route makes one
// service call; none re-saves state it did not change (the bug E2B's timeout
// route had). Labels, idle timers and the compat blob are replicated only for
// a failover=recreate sandbox, the one case a recreate reads them back, and
// a repeat of the same value writes nothing. Resize is replicated for every
// sandbox.
func TestDaytonaRoutesRaftWrites(t *testing.T) {
	type step struct {
		name         string
		method, path string
		body         string
		writes       [2]int // Raft spec writes this step adds: {default, failover=recreate}
	}
	steps := []step{
		{"set labels", http.MethodPut, "/labels", `{"labels":{"team":"a"}}`, [2]int{0, 1}},
		{"same labels again", http.MethodPut, "/labels", `{"labels":{"team":"a"}}`, [2]int{0, 0}},
		{"set auto-stop", http.MethodPost, "/autostop/15", ``, [2]int{0, 1}},
		{"same auto-stop again", http.MethodPost, "/autostop/15", ``, [2]int{0, 0}},
		{"set auto-delete", http.MethodPost, "/autodelete/30", ``, [2]int{0, 1}},
		{"set auto-archive (compat blob)", http.MethodPost, "/autoarchive/60", ``, [2]int{0, 1}},
		{"same auto-archive again", http.MethodPost, "/autoarchive/60", ``, [2]int{0, 0}},
		{"resize", http.MethodPost, "/resize", `{"cpu":2}`, [2]int{1, 1}},
	}
	for policy, label := range []string{"default sandbox", "failover=recreate sandbox"} {
		t.Run(label, func(t *testing.T) {
			env := newDaytonaContractEnv(t)
			sb := env.seedSandbox(contractSandboxSeed{ID: "sb-raft-writes", Name: "raft-writes"})
			if policy == 1 {
				coverage97Exec(t, env.store, "UPDATE sandboxes SET failover_policy = 'recreate' WHERE id = '"+sb.ID+"'")
			}
			counter := &specWriteCounter{Noop: cluster.NewNoop("self", "http://self", ""), spec: models.CreateSandboxRequest{Image: "ubuntu:22.04"}}
			env.service.AttachCluster(counter)

			for _, s := range steps {
				writesBefore, readsBefore := counter.counts()
				req, err := http.NewRequest(s.method, env.baseURL+"/sandbox/"+sb.ID+s.path, strings.NewReader(s.body))
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Content-Type", "application/json")
				resp, err := env.server.Client().Do(req)
				if err != nil {
					t.Fatalf("%s: %v", s.name, err)
				}
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("%s: status = %d, want 200", s.name, resp.StatusCode)
				}
				writes, reads := counter.counts()
				if got := writes - writesBefore; got != s.writes[policy] {
					t.Errorf("%s: Raft spec writes = %d, want %d", s.name, got, s.writes[policy])
				}
				if policy == 0 && s.writes[0] == 0 && reads != readsBefore {
					t.Errorf("%s: spec reads (server round trips) = %d, want 0", s.name, reads-readsBefore)
				}
			}
		})
	}
}
