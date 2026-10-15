//go:build integration

package suite

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// snapshotOnOwnedSandbox creates a sandbox (placed on some owner node) and
// commits a snapshot from it, so the snapshot's home node is that owner. It
// returns the snapshot name and the still-running source sandbox (whose owner
// nonOwnerAPI resolves). The sandbox stays alive for the test's duration.
func snapshotOnOwnedSandbox(t *testing.T, c *harness.Client, ctx context.Context, label string) (string, *microvm.Sandbox) {
	t.Helper()
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)
	name := fcSnapshotName(t, label)
	if _, err := c.SDK().CreateSnapshot(ctx, sb.ID, name); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = c.SDK().DeleteSnapshot(cctx, name)
	})
	return name, sb
}

// getWithRetry polls a GET until it returns want (or a deadline), to ride out
// the brief FSM-replication window after a snapshot's home is registered.
func getWithRetry(t *testing.T, ctx context.Context, baseURL, path string, want int) (int, []byte) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	var st int
	var body []byte
	for {
		st, body = fcDo(t, ctx, http.MethodGet, baseURL, path, nil, nil)
		if st == want || time.Now().After(deadline) {
			return st, body
		}
		time.Sleep(3 * time.Second)
	}
}

// UC-247 — a v1 snapshot get-by-name is routed to the holder from a non-owner.
func TestSnapshotGetRoutesFromNonOwner(t *testing.T) {
	harness.Require(t, sc, "UC-247")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	name, sb := snapshotOnOwnedSandbox(t, c, ctx, "route-get")
	nonOwner := nonOwnerAPI(t, c, sb.ID)
	st, body := getWithRetry(t, ctx, nonOwner, "/v1/snapshots/"+name, http.StatusOK)
	if st != http.StatusOK {
		t.Fatalf("get snapshot via non-owner = %d, want 200 (home-node routing); body=%s", st, string(body))
	}
	if !strings.Contains(string(body), name) {
		t.Fatalf("routed get body does not mention %q: %s", name, string(body))
	}
}

// UC-248 — a v1 snapshot delete is routed to the holder from a non-owner and
// removes it cluster-wide.
func TestSnapshotDeleteRoutesFromNonOwner(t *testing.T) {
	harness.Require(t, sc, "UC-248")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	name, sb := snapshotOnOwnedSandbox(t, c, ctx, "route-del")
	nonOwner := nonOwnerAPI(t, c, sb.ID)
	// Make sure routing sees the home first (replication window).
	if st, body := getWithRetry(t, ctx, nonOwner, "/v1/snapshots/"+name, http.StatusOK); st != http.StatusOK {
		t.Fatalf("pre-delete get via non-owner = %d, want 200; body=%s", st, string(body))
	}
	st, body := fcDo(t, ctx, http.MethodDelete, nonOwner, "/v1/snapshots/"+name, nil, nil)
	if st != http.StatusNoContent {
		t.Fatalf("delete via non-owner = %d, want 204; body=%s", st, string(body))
	}
	// Gone cluster-wide: a get through the ingress is now 404.
	if st, body := getWithRetry(t, ctx, "", "/v1/snapshots/"+name, http.StatusNotFound); st != http.StatusNotFound {
		t.Fatalf("get after cluster-wide delete = %d, want 404; body=%s", st, string(body))
	}
}

// UC-249 — a Daytona snapshot get-by-id is routed to the holder from a non-owner.
func TestDaytonaSnapshotGetRoutesFromNonOwner(t *testing.T) {
	harness.Require(t, sc, "UC-249")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	name, sb := snapshotOnOwnedSandbox(t, c, ctx, "dt-route")
	nonOwner := nonOwnerAPI(t, c, sb.ID)
	st, body := getWithRetry(t, ctx, nonOwner, "/daytona/snapshots/"+name, http.StatusOK)
	if st != http.StatusOK {
		t.Fatalf("Daytona get via non-owner = %d, want 200; body=%s", st, string(body))
	}
}

// UC-250 — an E2B template(snapshot) delete-by-id is routed to the holder from a
// non-owner. The E2B id is taken from the facade's own list (no transform
// guessing).
func TestE2BTemplateDeleteRoutesFromNonOwner(t *testing.T) {
	harness.Require(t, sc, "UC-250")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	name, sb := snapshotOnOwnedSandbox(t, c, ctx, "e2b-route")
	// Resolve the E2B snapshot id from the catalogue (matches our name).
	var e2bID string
	deadline := time.Now().Add(90 * time.Second)
	for e2bID == "" && time.Now().Before(deadline) {
		st, body := fcDo(t, ctx, http.MethodGet, "", "/e2b/snapshots?limit=500", nil, nil)
		if st == http.StatusOK {
			var items []e2bSnapshotInfo
			fcDecode(t, body, &items)
			for _, it := range items {
				for _, n := range it.Names {
					if strings.Contains(n, name) {
						e2bID = it.SnapshotID
					}
				}
			}
		}
		if e2bID == "" {
			time.Sleep(3 * time.Second)
		}
	}
	if e2bID == "" {
		t.Fatalf("could not resolve E2B snapshot id for %q", name)
	}
	nonOwner := nonOwnerAPI(t, c, sb.ID)
	st, body := fcDo(t, ctx, http.MethodDelete, nonOwner, "/e2b/templates/"+e2bID, nil, nil)
	if st != http.StatusNoContent && st != http.StatusOK {
		t.Fatalf("E2B template delete via non-owner = %d, want 204/200; body=%s", st, string(body))
	}
}

// UC-251 — a snapshot committed on one node is routable for get from every
// other SSH-reachable node (B6 fan-in).
func TestSnapshotGetRoutableFromEveryNode(t *testing.T) {
	harness.Require(t, sc, "UC-251")
	c := client(t)
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	name, sb := snapshotOnOwnedSandbox(t, c, ctx, "fanin")
	owner := resolvePlacementOwner(t, c, sb.ID)
	if owner == "" {
		t.Fatal("no placement owner recorded")
	}
	checked := 0
	for _, n := range targets.Nodes {
		if _, ok := harness.SSHTarget(n); !ok {
			continue
		}
		if heteroNodeID(t, c, targets, n.Name) == owner {
			continue // the holder serves it locally; we want the routed path
		}
		url := "http://" + harness.SSHForward(t, n, "127.0.0.1:21212")
		if st, body := getWithRetry(t, ctx, url, "/v1/snapshots/"+name, http.StatusOK); st != http.StatusOK {
			t.Fatalf("get via node %s = %d, want 200 (routing); body=%s", n.Name, st, string(body))
		}
		checked++
	}
	if checked == 0 {
		t.Skip("no non-owner SSH-reachable node to route from")
	}
	t.Logf("routed snapshot get verified from %d non-owner node(s)", checked)
}

// UC-261 — snapshot home-node routing works on a heterogeneous cluster (gated to
// scenarios that provision Firecracker, i.e. cluster-hetero).
func TestSnapshotRoutingOnHetero(t *testing.T) {
	harness.Require(t, sc, "UC-261")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()

	name, sb := snapshotOnOwnedSandbox(t, c, ctx, "hetero-route")
	nonOwner := nonOwnerAPI(t, c, sb.ID)
	if st, body := getWithRetry(t, ctx, nonOwner, "/v1/snapshots/"+name, http.StatusOK); st != http.StatusOK {
		t.Fatalf("hetero routed get = %d, want 200; body=%s", st, string(body))
	}
}

// UC-262 — create-from-snapshot works across nodes: a snapshot committed on one
// node yields a running sandbox when created through the ingress (which may
// place it elsewhere), proving the snapshot image is usable cluster-wide.
func TestCreateFromSnapshotAcrossNodes(t *testing.T) {
	harness.Require(t, sc, "UC-262")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	snapName := fcSnapshotName(t, "xnode")
	src := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, src)
	snap, err := c.SDK().CreateSnapshot(ctx, src.ID, snapName)
	if err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = c.SDK().DeleteSnapshot(cctx, snapName)
	})

	var derived *microvm.Sandbox
	deadline := time.Now().Add(4 * time.Minute)
	for {
		derived, err = c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{Image: snap.Image, Name: harness.UniqueName(sc, t)})
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("create from snapshot never succeeded across the cluster: %v", err)
		}
		time.Sleep(5 * time.Second)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = c.SDK().Destroy(cctx, derived.ID)
	})
	waitRunning(t, derived)
	if res, err := derived.ExecCommand(ctx, "echo uc262-ok"); err != nil || !strings.Contains(res.Stdout, "uc262-ok") {
		t.Fatalf("exec on cross-node snapshot sandbox = %q, %v", res.Stdout, err)
	}
}
