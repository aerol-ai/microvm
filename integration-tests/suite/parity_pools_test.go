//go:build integration

package suite

// Live checks for warm pools as an API object (plans/agent-sandbox-feature-
// parity.md W1-W3). The docker warm pool is default-off on purpose; these
// cases need the docker-pool capability, which run.sh turns into
// docker.pool.enabled for the scenario (cluster-3-mixed-docker).

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	"github.com/aerol-ai/microvm/pkg/models"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// parityPoolImage is pulled by other cases already, and is not the env pin
// (alpine:3.20): deleting its entry must drain it, not fall back to a pin.
const parityPoolImage = "python:3.12-alpine"

// parityPoolWait bounds a pool reaching its target: a pull on each server,
// then one park per slot, plus a sync interval and a capacity heartbeat.
const parityPoolWait = 4 * time.Minute

// putParityPool creates the entry and deletes it when the test ends.
func putParityPool(t *testing.T, c *harness.Client, depth int) models.WarmPool {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	pool, err := c.SDK().PutWarmPool(ctx, parityPoolImage, sdktypes.WarmPoolOptions{Depth: depth})
	if err != nil {
		t.Fatalf("PutWarmPool(%s, %d): %v", parityPoolImage, depth, err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		if err := c.SDK().DeleteWarmPool(cctx, parityPoolImage); err != nil {
			t.Logf("cleanup: DeleteWarmPool(%s): %v", parityPoolImage, err)
		}
	})
	return pool
}

// waitParityPool polls the entry until ok holds for its status.
func waitParityPool(t *testing.T, c *harness.Client, what string, ok func(models.WarmPoolStatus) bool) models.WarmPool {
	t.Helper()
	deadline := time.Now().Add(parityPoolWait)
	var last models.WarmPool
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		pool, err := c.SDK().GetWarmPool(ctx, parityPoolImage)
		cancel()
		if err == nil {
			last = pool
			if pool.Status != nil && ok(*pool.Status) {
				return pool
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("warm pool %s never reached %s; last = %+v (err %v)", parityPoolImage, what, statusOf(last), err)
		}
		time.Sleep(5 * time.Second)
	}
}

func statusOf(p models.WarmPool) models.WarmPoolStatus {
	if p.Status == nil {
		return models.WarmPoolStatus{}
	}
	return *p.Status
}

// fullAt is "every server that reports the entry is at depth, and ready
// equals the target".
func fullAt(depth int) func(models.WarmPoolStatus) bool {
	return func(s models.WarmPoolStatus) bool {
		if len(s.Servers) == 0 || s.Ready != s.Target {
			return false
		}
		for _, srv := range s.Servers {
			if srv.Target != depth || srv.Ready != depth || srv.Stale {
				return false
			}
		}
		return true
	}
}

// UC-417 — An admin creates a warm-pool entry for an image; every server
// with a warm pool parks that many sandboxes, and the entry's status shows
// ready reach the target in total and per server.
func TestParityWarmPoolReachesTarget(t *testing.T) {
	harness.Require(t, sc, "UC-417")
	c := client(t)
	const depth = 2
	put := putParityPool(t, c, depth)
	if put.Image != parityPoolImage || put.Depth != depth || put.Generation < 1 {
		t.Fatalf("PutWarmPool = %+v", put)
	}
	again := putParityPool(t, c, depth)
	if again.Generation != put.Generation {
		t.Fatalf("the same PUT twice must keep the generation: %d then %d", put.Generation, again.Generation)
	}
	pool := waitParityPool(t, c, "ready == target on every server", fullAt(depth))
	t.Logf("UC-417: %s ready %d/%d on %d server(s)", parityPoolImage, pool.Status.Ready, pool.Status.Target, len(pool.Status.Servers))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pools, err := c.SDK().ListWarmPools(ctx)
	if err != nil || !slices.ContainsFunc(pools, func(p models.WarmPool) bool { return p.Image == parityPoolImage && p.Status != nil }) {
		t.Fatalf("ListWarmPools = %+v, %v; want the entry with its status", pools, err)
	}
}

// UC-418 — A create from a pooled image is served by a warm sandbox: its
// Server-Timing has a docker_pool stage and no docker_create stage (an
// adopted container never calls /containers/create).
func TestParityWarmPoolCreateIsWarmHit(t *testing.T) {
	harness.Require(t, sc, "UC-418")
	c := client(t)
	putParityPool(t, c, 2)
	waitParityPool(t, c, "ready == target on every server", fullAt(2))
	// Placement may pick any server; each has slots, so every probe should
	// hit. A few probes ride out a slot that is being refilled.
	for attempt := 1; attempt <= 5; attempt++ {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		sb, err := c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), Image: parityPoolImage})
		cancel()
		if err != nil {
			t.Fatalf("create from %s: %v", parityPoolImage, err)
		}
		stages, ok := c.LastServerCreateStages()
		destroyBest(c, sb.ID)
		_, pool := stages["docker_pool"]
		_, cold := stages["docker_create"]
		if ok && pool && !cold {
			t.Logf("UC-418: create %d of %s was a warm hit (stages %v)", attempt, sb.ID, stages)
			return
		}
		t.Logf("UC-418: create %d was not a warm hit (stages %v, timing seen %v)", attempt, stages, ok)
		time.Sleep(10 * time.Second)
	}
	t.Fatalf("no create from %s was served by its warm pool", parityPoolImage)
}

// UC-419 — In a cluster the entry reaches every server: each node that can
// run sandboxes reports the entry at its depth, whichever node took the PUT.
func TestParityWarmPoolReplicatesToEveryNode(t *testing.T) {
	harness.Require(t, sc, "UC-419")
	c := client(t)
	members, err := getMembers(t, c)
	if err != nil {
		t.Fatalf("cluster members: %v", err)
	}
	var workers []string
	for _, m := range members {
		if (m.Role == "" || m.Role == "mixed" || m.Role == "worker") && !m.Drained {
			workers = append(workers, m.NodeID)
		}
	}
	if len(workers) < 2 {
		t.Fatalf("need at least two nodes that run sandboxes, have %v", workers)
	}
	const depth = 1
	putParityPool(t, c, depth)
	pool := waitParityPool(t, c, "the entry on every node", func(s models.WarmPoolStatus) bool {
		for _, id := range workers {
			if !slices.ContainsFunc(s.Servers, func(srv models.WarmPoolServerStatus) bool { return srv.NodeID == id && srv.Target == depth }) {
				return false
			}
		}
		return true
	})
	t.Logf("UC-419: %d node(s) carry the entry: %+v", len(workers), pool.Status.Servers)
}

// UC-420 — Deleting the entry drains it: no server reports it any more, the
// parked slots it held are given back, and a GET answers 404. A second
// delete succeeds.
func TestParityWarmPoolDeleteDrains(t *testing.T) {
	harness.Require(t, sc, "UC-420")
	c := client(t)
	const depth = 2
	putParityPool(t, c, depth)
	full := waitParityPool(t, c, "ready == target on every server", fullAt(depth))
	before := parkedSlots(t, c)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := c.SDK().DeleteWarmPool(ctx, parityPoolImage); err != nil {
		t.Fatalf("DeleteWarmPool: %v", err)
	}
	if err := c.SDK().DeleteWarmPool(ctx, parityPoolImage); err != nil {
		t.Fatalf("a second DeleteWarmPool must succeed: %v", err)
	}
	if _, err := c.SDK().GetWarmPool(ctx, parityPoolImage); !errors.Is(err, microvm.ErrNotFound) {
		t.Fatalf("GetWarmPool after delete = %v, want 404", err)
	}
	deadline := time.Now().Add(parityPoolWait)
	for {
		reporting := serversReporting(t, c, parityPoolImage)
		after := parkedSlots(t, c)
		if reporting == 0 && after <= before-full.Status.Ready {
			t.Logf("UC-420: parked slots %d -> %d after deleting an entry that held %d", before, after, full.Status.Ready)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the pool never drained: %d server(s) still report %s; parked %d -> %d, want a drop of %d",
				reporting, parityPoolImage, before, after, full.Status.Ready)
		}
		time.Sleep(5 * time.Second)
	}
}

// memberCapacity is the part of /v1/cluster/members (or /v1/capacity on a
// single node) the drain check reads.
type memberCapacity struct {
	ParkedSlots int `json:"parked_slots"`
	WarmPools   []struct {
		Image string `json:"image"`
	} `json:"warm_pools"`
}

func fleetCapacity(t *testing.T, c *harness.Client) []memberCapacity {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if !sc.Has(harness.CapCluster) {
		var one memberCapacity
		if err := c.GetJSON(ctx, "/v1/capacity", &one); err != nil {
			t.Fatalf("capacity: %v", err)
		}
		return []memberCapacity{one}
	}
	var resp struct {
		Members []struct {
			Alive    bool           `json:"alive"`
			Capacity memberCapacity `json:"capacity"`
		} `json:"members"`
	}
	if err := c.GetJSON(ctx, "/v1/cluster/members", &resp); err != nil {
		t.Fatalf("cluster members: %v", err)
	}
	var out []memberCapacity
	for _, m := range resp.Members {
		if m.Alive {
			out = append(out, m.Capacity)
		}
	}
	return out
}

func parkedSlots(t *testing.T, c *harness.Client) int {
	total := 0
	for _, m := range fleetCapacity(t, c) {
		total += m.ParkedSlots
	}
	return total
}

func serversReporting(t *testing.T, c *harness.Client, image string) int {
	n := 0
	for _, m := range fleetCapacity(t, c) {
		for _, p := range m.WarmPools {
			if p.Image == image {
				n++
			}
		}
	}
	return n
}

// UC-421 — The warm-pool API is for admins only: a runner token and a
// viewer token bound to every team are refused with a 403 naming
// fleet.admin; an admin token bound to every team is allowed.
func TestParityWarmPoolNonAdminRefused(t *testing.T) {
	harness.Require(t, sc, "UC-421")
	runner := mintToken(t, "uc421-run", "runner", harness.TeamPayments)
	viewer := mintToken(t, "uc421-view", "viewer", "*")
	admin := mintToken(t, "uc421-admin", "admin", "*")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	path := "/v1/warm-pools/" + parityPoolImage
	for _, tok := range []struct {
		name string
		api  *harness.APIClient
	}{{"runner", runner.API}, {"viewer", viewer.API}} {
		for _, call := range []struct {
			method, path string
			body         any
		}{
			{http.MethodGet, "/v1/warm-pools", nil},
			{http.MethodGet, path, nil},
			{http.MethodPut, path, models.WarmPoolRequest{Depth: 1}},
			{http.MethodDelete, path, nil},
		} {
			resp, err := tok.api.Do(ctx, call.method, call.path, call.body)
			if err != nil {
				t.Fatalf("%s %s %s: %v", tok.name, call.method, call.path, err)
			}
			if resp.Status != http.StatusForbidden || !strings.Contains(string(resp.Body), "fleet.admin") {
				t.Fatalf("%s %s %s = %s, want 403 naming fleet.admin", tok.name, call.method, call.path, resp)
			}
		}
	}
	resp, err := admin.API.Do(ctx, http.MethodGet, "/v1/warm-pools", nil)
	if err != nil || resp.Status != http.StatusOK {
		t.Fatalf("admin GET /v1/warm-pools = %s, %v; want 200", resp, err)
	}
}

// UC-422 — An entry that follows demand (min 0, max 2) starts with no
// warm sandboxes on any server; a few creates from the image raise the
// target of the server that served them within a sample window, and its
// pool then parks sandboxes to that target.
func TestParityWarmPoolFollowsDemand(t *testing.T) {
	harness.Require(t, sc, "UC-422")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	pool, err := c.SDK().PutWarmPool(ctx, parityPoolImage, sdktypes.WarmPoolOptions{MinDepth: 0, MaxDepth: 2})
	cancel()
	if err != nil || pool.MaxDepth != 2 || pool.Depth != 0 {
		t.Fatalf("PutWarmPool(min 0, max 2) = %+v, %v", pool, err)
	}
	t.Cleanup(func() {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Minute)
		defer ccancel()
		_ = c.SDK().DeleteWarmPool(cctx, parityPoolImage)
	})
	// The entry reaches each server at its floor: no target, nothing parked.
	waitParityPool(t, c, "every server at target 0", func(s models.WarmPoolStatus) bool {
		return len(s.Servers) > 0 && s.Target == 0 && s.Ready == 0
	})
	// Steady demand: a create every 10 s while polling, so whichever
	// servers placement picks keep a non-zero average across the 15 s sample
	// windows, the way a real queue of work would. A burst followed by
	// silence decays back to zero within about a minute, which a status
	// poll can miss. Each poll logs every server, so a failure shows whether
	// targets never moved or slots never parked.
	deadline := time.Now().Add(parityPoolWait)
	for i := 1; ; i++ {
		cctx, ccancel := context.WithTimeout(context.Background(), 2*time.Minute)
		sb, err := c.SDK().Create(cctx, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t), Image: parityPoolImage})
		ccancel()
		if err != nil {
			t.Fatalf("create %d from %s: %v", i, parityPoolImage, err)
		}
		destroyBest(c, sb.ID)

		gctx, gcancel := context.WithTimeout(context.Background(), 30*time.Second)
		pool, err := c.SDK().GetWarmPool(gctx, parityPoolImage)
		gcancel()
		if err == nil && pool.Status != nil {
			t.Logf("UC-422: after create %d: %+v", i, pool.Status.Servers)
			for _, srv := range pool.Status.Servers {
				if srv.Target >= 1 && srv.Ready >= 1 && srv.Target <= 2 {
					t.Logf("UC-422: server %s follows demand: target %d, ready %d", srv.NodeID, srv.Target, srv.Ready)
					return
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("warm pool %s never reached a server's target and ready above 0 under steady demand; last = %+v (err %v)", parityPoolImage, statusOf(pool), err)
		}
		time.Sleep(10 * time.Second)
	}
}
