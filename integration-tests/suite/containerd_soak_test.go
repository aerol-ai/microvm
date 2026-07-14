//go:build integration

package suite

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
	microvm "github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// Toolbox listen port used for peer reachability probes. Matches the
// daemon default (SB_TOOLBOX_PORT); sandboxes always run toolboxd there
// when toolbox is enabled (create default).
const neighborToolboxPort = 2280

func requireSSHTargets(t *testing.T) *harness.IntegrationTargets {
	t.Helper()
	targets := harness.LoadIntegrationTargets()
	if targets == nil {
		t.Skip("AEROL_INTEGRATION_TARGETS not set (run via integration-tests/run.sh)")
	}
	if _, ok := harness.PickSSHNode(targets); !ok {
		t.Skip("no SSH-reachable node in integration targets")
	}
	return targets
}

func requireSSHNode(t *testing.T) harness.IntegrationNode {
	t.Helper()
	node, ok := harness.PickSSHNode(requireSSHTargets(t))
	if !ok {
		t.Fatal("no SSH node")
	}
	return node
}

// UC-99 — egress-blocked sandbox cannot reach a neighbor on the same bridge
// (plans/containerd-engine.md §8 neighbor-isolation gate). Control sandbox
// proves peer traffic is otherwise possible; blocked sandbox must fail the
// same probe.
//
// Neighbor isolation is a SAME-BRIDGE property: the containerd CNI bridge is
// node-local, so a cross-node peer is unreachable for reasons unrelated to the
// egress firewall. A cluster scatters sandboxes across nodes, so victim,
// control and blocked must be co-located on ONE node before the probe is
// meaningful. Power-of-two placement load-BALANCES (it actively avoids the
// busiest node), so we cannot pin a node by retrying onto the victim's; instead
// coLocatedNeighborhood embraces the spread and waits for one node to naturally
// accumulate the trio. On a single node every create lands together.
func TestNeighborIsolationEgressBlocked(t *testing.T) {
	harness.Require(t, sc, "UC-99")
	c := client(t)

	victim, control, blocked := coLocatedNeighborhood(t, c)
	if victim.ContainerIP == "" {
		t.Fatal("victim sandbox missing container_ip")
	}

	if !tcpProbe(t, control, victim.ContainerIP, neighborToolboxPort) {
		t.Fatalf("control cannot reach co-located neighbor %s:%d — bridge peer traffic broken; cannot prove isolation",
			victim.ContainerIP, neighborToolboxPort)
	}

	if tcpProbe(t, blocked, victim.ContainerIP, neighborToolboxPort) {
		t.Fatalf("neighbor isolation FAILED: NetworkBlockAll sandbox reached peer %s:%d",
			victim.ContainerIP, neighborToolboxPort)
	}
}

// resolveOwnerNode polls the FSM placement view until sandboxID has an owner
// node. Returns "" if the deployment never reports one (single-node with no
// cluster placement view — one node, one bridge); a wrong "" on a real cluster
// is caught downstream by the reachability assertion failing loudly.
func resolveOwnerNode(t *testing.T, c *harness.Client, sandboxID string) string {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		node, err := c.OwnerNodeID(ctx, sandboxID)
		cancel()
		if err == nil && node != "" {
			return node
		}
		time.Sleep(2 * time.Second)
	}
	return ""
}

// coLocatedNeighborhood returns a victim + control (both normal) and a blocked
// (NetworkBlockAll) sandbox, all placed on the SAME node — the precondition for
// a meaningful neighbor-isolation probe. Because power-of-two placement
// load-balances (it will not pile onto one node on request), we don't try to
// pin a node; we create sandboxes, bucket each by its FSM owner node, and stop
// as soon as one node holds >=2 normal + >=1 blocked. An even spread guarantees
// a node accumulates the trio within a handful of creates. On single-node every
// sandbox shares the one node so the first two rounds suffice. All created
// sandboxes are destroyed via a single cleanup.
func coLocatedNeighborhood(t *testing.T, c *harness.Client) (victim, control, blocked *microvm.Sandbox) {
	t.Helper()
	type bucket struct{ normal, blocked []*microvm.Sandbox }
	byNode := map[string]*bucket{}
	var created []*microvm.Sandbox
	t.Cleanup(func() {
		for _, sb := range created {
			cctx, cancel := context.WithTimeout(context.Background(), time.Minute)
			_ = c.SDK().Destroy(cctx, sb.ID)
			cancel()
		}
	})
	// Cluster admits ~50+ default sandboxes; 24 is a safe ceiling that still
	// converges on an even 3-node spread long before it.
	const maxCreates = 24
	for len(created) < maxCreates {
		blockAll := len(created)%2 == 1 // alternate normal, blocked, ...
		public := true
		opts := sdktypes.CreateSandboxOptions{
			Name:               fmt.Sprintf("%s-%d", harness.UniqueName(sc, t), len(created)),
			Image:              harness.DefaultImage,
			AllowPublicTraffic: &public,
			NetworkBlockAll:    blockAll,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
		sb, err := c.SDK().Create(ctx, opts)
		cancel()
		if err != nil {
			t.Fatalf("neighbor create (blockAll=%v): %v", blockAll, err)
		}
		created = append(created, sb)
		waitRunning(t, sb)

		node := resolveOwnerNode(t, c, sb.ID)
		bk := byNode[node]
		if bk == nil {
			bk = &bucket{}
			byNode[node] = bk
		}
		if blockAll {
			bk.blocked = append(bk.blocked, sb)
		} else {
			bk.normal = append(bk.normal, sb)
		}
		if len(bk.normal) >= 2 && len(bk.blocked) >= 1 {
			t.Logf("UC-99 co-located on node %q (%d normal, %d blocked) after %d creates",
				node, len(bk.normal), len(bk.blocked), len(created))
			return bk.normal[0], bk.normal[1], bk.blocked[0]
		}
	}
	t.Fatalf("could not co-locate 2 normal + 1 blocked sandbox on one node within %d creates", maxCreates)
	return nil, nil, nil
}

// UC-100 — after sandboxd restart, live sandboxes remain usable and
// admin/reconcile stays clean (plans/containerd-engine.md Phase 5).
func TestSandboxdRestartReconcile(t *testing.T) {
	harness.Require(t, sc, "UC-100")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (AEROL_ALLOW_DISRUPTIVE)")
	}
	targets := requireSSHTargets(t)
	c := client(t)

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	// Restart every node so cluster placements survive regardless of owner.
	harness.RestartSystemdUnitOnAll(t, targets, "sandboxd")
	waitAPIHealthy(t, c)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	got, err := c.SDK().Get(ctx, sb.ID)
	if err != nil {
		t.Fatalf("get after sandboxd restart: %v", err)
	}
	if string(got.Status) != "started" {
		t.Fatalf("sandbox status after restart = %q, want started", got.Status)
	}
	res, err := sb.ExecCommand(ctx, "echo after-sandboxd-restart")
	if err != nil {
		t.Fatalf("exec after sandboxd restart: %v", err)
	}
	if !strings.Contains(res.Stdout+res.Stderr, "after-sandboxd-restart") {
		t.Fatalf("unexpected exec output: stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
	if err := c.SDK().Reconcile(ctx); err != nil {
		t.Fatalf("reconcile after sandboxd restart: %v", err)
	}
}

// UC-101 — containerd restart leaves running shims + event path healthy.
func TestContainerdRestartShimsSurvive(t *testing.T) {
	harness.Require(t, sc, "UC-101")
	if !harness.DisruptiveAllowed() {
		t.Skip("disruptive tests disabled (AEROL_ALLOW_DISRUPTIVE)")
	}
	targets := requireSSHTargets(t)
	c := client(t)

	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)

	harness.RestartSystemdUnitOnAll(t, targets, "containerd")
	// sandboxd may need a moment to resubscribe to the event stream.
	waitAPIHealthy(t, c)
	time.Sleep(3 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	res, err := sb.ExecCommand(ctx, "echo after-containerd-restart")
	if err != nil {
		t.Fatalf("exec after containerd restart (shim should survive): %v", err)
	}
	if !strings.Contains(res.Stdout+res.Stderr, "after-containerd-restart") {
		t.Fatalf("unexpected exec output: stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
}

// UC-102 — dockerd restart must not drop the AEROLVM-USER FORWARD jump while
// the containerd engine owns sandboxes (coexistence).
func TestDockerdCoexistenceAEROLVMUserSurvives(t *testing.T) {
	harness.Require(t, sc, "UC-102")
	c := client(t)
	sb := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, sb)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	res, err := sb.ExecCommand(ctx, "echo coexistence-ok")
	if err != nil {
		t.Fatalf("exec: %v", err)
	}
	if strings.TrimSpace(res.Stdout+res.Stderr) == "" {
		t.Fatal("empty exec output")
	}
	if !harness.DisruptiveAllowed() {
		t.Log("soft coexistence create/exec ok; dockerd restart assert deferred (AEROL_ALLOW_DISRUPTIVE)")
		return
	}
	node := requireSSHNode(t)
	if !harness.HostHasAEROLVMUserJump(t, node) {
		t.Fatal("AEROLVM-USER FORWARD jump missing before dockerd restart")
	}
	harness.RestartSystemdUnit(t, node, "docker")
	waitAPIHealthy(t, c)
	if !harness.HostHasAEROLVMUserJump(t, node) {
		t.Fatal("AEROLVM-USER FORWARD jump missing AFTER dockerd restart")
	}
	res, err = sb.ExecCommand(ctx, "echo after-dockerd-restart")
	if err != nil {
		t.Fatalf("exec after dockerd restart: %v", err)
	}
	if !strings.Contains(res.Stdout+res.Stderr, "after-dockerd-restart") {
		t.Fatalf("unexpected exec output: stdout=%q stderr=%q", res.Stdout, res.Stderr)
	}
}

func waitAPIHealthy(t *testing.T, c *harness.Client) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		var body map[string]any
		err := c.GetJSON(ctx, "/health", &body)
		cancel()
		if err == nil {
			return
		}
		last = err
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("API not healthy after host restart: %v", last)
}
