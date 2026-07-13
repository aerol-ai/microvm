//go:build integration

package suite

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/integration-tests/suite/harness"
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
func TestNeighborIsolationEgressBlocked(t *testing.T) {
	harness.Require(t, sc, "UC-99")
	c := client(t)

	victim := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, victim)
	if victim.ContainerIP == "" {
		t.Fatal("victim sandbox missing container_ip")
	}

	control := c.NewSandbox(t, sdktypes.CreateSandboxOptions{Name: harness.UniqueName(sc, t)})
	waitRunning(t, control)
	if !tcpProbe(t, control, victim.ContainerIP, neighborToolboxPort) {
		t.Fatalf("control cannot reach neighbor %s:%d — bridge peer traffic broken; cannot prove isolation",
			victim.ContainerIP, neighborToolboxPort)
	}

	blocked := c.NewSandbox(t, sdktypes.CreateSandboxOptions{
		Name:            harness.UniqueName(sc, t),
		NetworkBlockAll: true,
	})
	waitRunning(t, blocked)
	if tcpProbe(t, blocked, victim.ContainerIP, neighborToolboxPort) {
		t.Fatalf("neighbor isolation FAILED: NetworkBlockAll sandbox reached peer %s:%d",
			victim.ContainerIP, neighborToolboxPort)
	}
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
