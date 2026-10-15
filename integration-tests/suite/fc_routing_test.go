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

// e2bSnapshotOnOwnedSandbox creates a sandbox THROUGH the E2B facade, waits for
// it to run, and snapshots it through the facade. The snapshot is then E2B-native:
// its name is committed in the facade's canonical (name:default) spelling, so the
// id the facade returns and reports in its list decodes back to the same name the
// home-node index was registered under — which is what lets a by-id request route
// cluster-wide. It returns the E2B snapshot id and the source sandbox id (whose
// owner is the snapshot's home). Both are cleaned up.
func e2bSnapshotOnOwnedSandbox(t *testing.T, ctx context.Context, label string) (string, string) {
	t.Helper()
	st, body := fcDo(t, ctx, http.MethodPost, "", "/e2b/sandboxes", map[string]any{"templateID": "base"}, nil)
	if st != http.StatusCreated {
		t.Fatalf("E2B create = %d, want 201; body=%s", st, string(body))
	}
	var created struct {
		SandboxID string `json:"sandboxID"`
	}
	fcDecode(t, body, &created)
	if created.SandboxID == "" {
		t.Fatalf("E2B create returned no sandboxID: %s", string(body))
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		fcDo(t, cctx, http.MethodDelete, "", "/e2b/sandboxes/"+created.SandboxID, nil, nil)
	})

	// The snapshot commit needs the sandbox to be running.
	deadline := time.Now().Add(4 * time.Minute)
	for {
		st, body := fcDo(t, ctx, http.MethodGet, "", "/e2b/sandboxes/"+created.SandboxID, nil, nil)
		if st == http.StatusOK {
			var dv struct {
				State string `json:"state"`
			}
			fcDecode(t, body, &dv)
			if dv.State == "running" {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("E2B sandbox %s never reached running", created.SandboxID)
		}
		time.Sleep(4 * time.Second)
	}

	snapName := fcSnapshotName(t, label)
	st, body = fcDo(t, ctx, http.MethodPost, "", "/e2b/sandboxes/"+created.SandboxID+"/snapshots", map[string]any{"name": snapName}, nil)
	if st != http.StatusCreated && st != http.StatusOK {
		t.Fatalf("E2B snapshot = %d, want 201/200; body=%s", st, string(body))
	}
	var snap struct {
		SnapshotID string `json:"snapshotID"`
	}
	fcDecode(t, body, &snap)
	if snap.SnapshotID == "" {
		t.Fatalf("E2B snapshot returned no snapshotID: %s", string(body))
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		fcDo(t, cctx, http.MethodDelete, "", "/e2b/templates/"+snap.SnapshotID, nil, nil)
	})
	return snap.SnapshotID, created.SandboxID
}

// UC-250 — an E2B template(snapshot) delete-by-id is routed to the holder from a
// non-owner. The snapshot is created through the E2B facade so it is E2B-native
// (canonical name), which is the path E2B clients use and the one the by-id
// home-node routing covers. (A v1-committed snapshot deleted through its E2B id
// is a cross-facade case: the E2B id encodes name:default while the row and the
// home index key are the raw name, so by-id routing misses and serves locally —
// a separate, documented gap, not what this UC asserts.)
func TestE2BTemplateDeleteRoutesFromNonOwner(t *testing.T) {
	harness.Require(t, sc, "UC-250")
	c := client(t)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()

	e2bID, sbID := e2bSnapshotOnOwnedSandbox(t, ctx, "e2b-route")
	nonOwner := nonOwnerAPI(t, c, sbID)
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
	if _, err := c.SDK().CreateSnapshot(ctx, src.ID, snapName); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_ = c.SDK().DeleteSnapshot(cctx, snapName)
	})

	// Create from the snapshot by NAME: the name resolves to the owner-namespaced
	// AOCR ref on whatever node the ingress and placement pick, so the snapshot's
	// pushed copy is what makes it usable cluster-wide. (The committed
	// aerolvm-snapshot/<hash> ref only resolves on the home node — see UC-260.)
	var derived *microvm.Sandbox
	var err error
	deadline := time.Now().Add(4 * time.Minute)
	for {
		derived, err = c.SDK().Create(ctx, sdktypes.CreateSandboxOptions{Image: snapName, Name: harness.UniqueName(sc, t)})
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
