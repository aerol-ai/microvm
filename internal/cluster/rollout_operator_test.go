package cluster

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
)

func operatorDriven() error {
	return stepErr(http.StatusConflict, upgradewire.ErrCodeOperatorDriven, "the Kubernetes operator upgrades this node")
}

// operatorSwap plays the operator: the node comes back on version.
func (g *rolloutRig) operatorSwap(id, version string) {
	g.nodes.mu.Lock()
	g.nodes.node(id).version = version
	g.nodes.mu.Unlock()
	g.host.setVersion(id, version)
}

// C13: operator-driven workers walk in order, one batch at a time, each
// cordoned and marked upgrading when its turn comes; the leader never calls
// their upgrader, and finishes each once it reports the target.
func TestRolloutDriverWaitsForTheOperatorInOrder(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 3)
	for _, id := range []string{"w1", "w2"} {
		g.nodes.nodes[id].stageErr = operatorDriven()
		g.nodes.nodes[id].applyErr = errors.New("the leader must not call an operator-driven node's upgrader")
	}
	g.start(func(r *RolloutRecord) { r.Batch = "1"; r.Hold = true; r.AllowDowntime = true })

	tickUntil := func(what string, ok func(r *RolloutRecord) bool) *RolloutRecord {
		t.Helper()
		for i := 0; i < 50; i++ {
			g.driver.tick(context.Background())
			if r := g.host.rollout(); ok(r) {
				return r
			}
		}
		r := g.host.rollout()
		t.Fatalf("never %s: %s", what, describeNodes(r))
		return nil
	}
	r := tickUntil("w1 upgrading", func(r *RolloutRecord) bool { return r.Nodes["w1"].State == upgradewire.NodeUpgrading })
	if !r.Nodes["w1"].Operator || !r.Nodes["w2"].Operator || r.Nodes["w3"].Operator {
		t.Fatalf("operator flags: w1 %v w2 %v w3 %v", r.Nodes["w1"].Operator, r.Nodes["w2"].Operator, r.Nodes["w3"].Operator)
	}
	if !g.host.drain["w1"] {
		t.Fatal("w1 not cordoned before its swap")
	}
	if r.Nodes["w1"].DeadlineUnixNano == 0 || r.Nodes["w1"].Op == "" {
		t.Fatalf("w1 upgrading without a deadline or op: %+v", r.Nodes["w1"])
	}
	// Pacing: nothing else restarts while the operator works on w1.
	for i := 0; i < 5; i++ {
		g.driver.tick(context.Background())
	}
	r = g.host.rollout()
	if r.Nodes["w2"].State == upgradewire.NodeUpgrading || r.Nodes["w3"].State == upgradewire.NodeUpgrading {
		t.Fatalf("a later batch started while w1 waited for the operator: %s", describeNodes(r))
	}
	if wire := RolloutAPIView(r, ActiveVersion{}); !wireNode(wire, "w1").Operator {
		t.Fatal("the status the operator reads does not flag w1")
	}

	g.operatorSwap("w1", "v2")
	r = tickUntil("w2 upgrading", func(r *RolloutRecord) bool { return r.Nodes["w2"].State == upgradewire.NodeUpgrading })
	if r.Nodes["w1"].State != upgradewire.NodeDone || g.host.drain["w1"] {
		t.Fatalf("w1 after the swap: %s, cordoned %v", r.Nodes["w1"].State, g.host.drain["w1"])
	}
	g.operatorSwap("w2", "v2")
	r = g.run(upgradewire.StateDone)
	if len(r.nodesIn(upgradewire.NodeDone)) != 4 {
		t.Fatalf("done with %s", describeNodes(r))
	}
	for _, id := range []string{"w1", "w2"} {
		if g.nodes.nodes[id].applyCalls != 0 {
			t.Fatalf("%s: the leader called its upgrader %d times", id, g.nodes.nodes[id].applyCalls)
		}
	}
	if g.nodes.nodes["w3"].applies != 1 {
		t.Fatal("the plain worker was not upgraded by the leader")
	}
}

// While a Raft server is too old to keep the flag, an operator-driven node
// is manual, as before C13: done once it reports the target.
func TestRolloutDriverOperatorNodeManualWithAnOldServer(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 1)
	g.host.oldServer = true
	g.nodes.nodes["w1"].stageErr = operatorDriven()
	g.start(func(r *RolloutRecord) { r.Hold = true; r.AllowDowntime = true })
	for i := 0; i < 10; i++ {
		g.driver.tick(context.Background())
	}
	r := g.host.rollout()
	if n := r.Nodes["w1"]; n.State != upgradewire.NodeManual || n.Operator || n.Error == "" {
		t.Fatalf("w1 = %+v", n)
	}
	g.operatorSwap("w1", "v2")
	g.run(upgradewire.StateDone)
}

// The leader resends an apply that never started, but an operator-driven
// node has no apply: it waits for the operator, and fails at its deadline
// (an image that cannot be pulled ends there).
func TestRolloutDriverOperatorNodeNoResendFailsAtDeadline(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 1)
	g.driver.applyResendAfter = time.Nanosecond
	g.nodes.nodes["w1"].stageErr = operatorDriven()
	g.nodes.nodes["w1"].applyErr = errors.New("no apply for an operator-driven node")
	g.start(func(r *RolloutRecord) { r.NodeTimeoutNanos = int64(time.Minute) })
	for i := 0; i < 10 && g.host.rollout().Nodes["w1"].State != upgradewire.NodeUpgrading; i++ {
		g.driver.tick(context.Background())
	}
	g.host.advance(30 * time.Second)
	for i := 0; i < 3; i++ {
		g.driver.tick(context.Background())
	}
	if n := g.host.rollout().Nodes["w1"]; n.State != upgradewire.NodeUpgrading || g.nodes.nodes["w1"].applyCalls != 0 {
		t.Fatalf("before the deadline w1 = %s, %d apply calls", n.State, g.nodes.nodes["w1"].applyCalls)
	}
	g.host.advance(time.Minute)
	g.driver.tick(context.Background())
	if n := g.host.rollout().Nodes["w1"]; n.State != upgradewire.NodeFailed {
		t.Fatalf("past the deadline w1 = %+v", n)
	}
}

func TestUpgradeNodeOperatorDriven(t *testing.T) {
	g := newUpgradeNodeRig(t, false)
	g.u.cfg.UpgradeDriver = config.UpgradeDriverOperator
	g.u.cfg.RemoteUpgrade = false // a pod sets both; the operator answer wins
	for _, step := range []string{UpgradeStepStage, UpgradeStepApply} {
		req := UpgradeStepRequest{RolloutID: "r1", Step: step, Direction: upgradewire.DirectionUpgrade, Version: "v2", Term: 1}
		if _, err := g.u.Step(context.Background(), "lead", req); stepCode(err) != upgradewire.ErrCodeOperatorDriven {
			t.Fatalf("%s = %v, want operator_driven", step, err)
		}
	}
	if len(g.launched) != 0 {
		t.Fatal("an operator-driven node launched an upgrader")
	}
}

// Eng review D6: on a Kubernetes-managed leader only the operator sets the
// version. Status, stop, resume and finalize still work.
func TestKubernetesManagedClusterRefusesManualApplyAndRollback(t *testing.T) {
	c := &Cluster{cfg: config.Config{UpgradeDriver: config.UpgradeDriverOperator}}
	ctx := context.Background()
	if code := rolloutCode(c.refuseUnlessOperator(ctx)); code != upgradewire.ErrCodeKubernetesManaged {
		t.Fatalf("manual = %q", code)
	}
	if err := c.refuseUnlessOperator(WithUpgradeDriver(ctx, " operator ")); err != nil {
		t.Fatalf("operator = %v", err)
	}
	if code := rolloutCode(c.refuseUnlessOperator(WithUpgradeDriver(ctx, "helm"))); code != upgradewire.ErrCodeKubernetesManaged {
		t.Fatalf("other driver = %q", code)
	}
	// A plain VM cluster: nothing changes (eng review D7).
	vm := &Cluster{}
	if err := vm.refuseUnlessOperator(ctx); err != nil {
		t.Fatalf("VM cluster = %v", err)
	}
}

func TestKubernetesManagedOnALiveLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestClusterWithCfg(t, "ldr-k8s", true, nil, func(cfg *config.Config) {
		cfg.UpgradeDriver = config.UpgradeDriverOperator
	})
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := context.Background()
	if _, _, err := c.ApplyRollout(ctx, "pat:admin", upgradewire.ApplyRequest{Version: "v9"}); rolloutCode(err) != upgradewire.ErrCodeKubernetesManaged {
		t.Fatalf("apply = %v", err)
	}
	if _, err := c.RolloutCommand(ctx, "pat:admin", RolloutRollback); rolloutCode(err) != upgradewire.ErrCodeKubernetesManaged {
		t.Fatalf("rollback = %v", err)
	}
	// Stop sets no version: it gets past the guard (and finds no rollout).
	if _, err := c.RolloutCommand(ctx, "pat:admin", RolloutStop); rolloutCode(err) == upgradewire.ErrCodeKubernetesManaged {
		t.Fatalf("stop refused as Kubernetes-managed: %v", err)
	}
	// The operator's apply gets past the guard to the usual checks.
	if _, _, err := c.ApplyRollout(WithUpgradeDriver(ctx, "operator"), "operator", upgradewire.ApplyRequest{Version: "v9"}); rolloutCode(err) == upgradewire.ErrCodeKubernetesManaged {
		t.Fatalf("operator apply refused: %v", err)
	}
}

// The operator's own request, end to end through ApplyRollout: an images
// rollout names no files, and a node of any CPU type takes it. The first
// version refused it at the per-node files check, so no spec.version
// change on Kubernetes ever started an upgrade.
func TestApplyImagesRolloutOnALiveLeader(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestClusterWithCfg(t, "ldr-img", true, nil, func(cfg *config.Config) {
		cfg.UpgradeDriver = config.UpgradeDriverOperator
	})
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	ctx := WithUpgradeDriver(context.Background(), "operator")
	out, created, err := c.ApplyRollout(ctx, "operator", upgradewire.ApplyRequest{
		Version: "v9.9.9", Source: upgradewire.SourceImages, Batch: "1", NodeTimeout: "15m", AllowDowntime: true,
	})
	if err != nil || out == nil || !created {
		t.Fatalf("images rollout = %+v created %v: %v", out, created, err)
	}
	if out.Source != upgradewire.SourceImages || out.TargetVersion != "v9.9.9" {
		t.Fatalf("rollout = %+v", out)
	}
}

func rolloutCode(err error) string {
	var re *RolloutError
	if errors.As(err, &re) {
		return re.Body.Error
	}
	return ""
}

func wireNode(r *upgradewire.Rollout, id string) upgradewire.RolloutNode {
	for _, n := range r.Nodes {
		if n.NodeID == id {
			return n
		}
	}
	return upgradewire.RolloutNode{}
}

// An images rollout (C13): only a Kubernetes-managed leader takes one, and
// it names no files.
func TestValidateApplyImagesSource(t *testing.T) {
	k8s := &Cluster{cfg: config.Config{UpgradeDriver: config.UpgradeDriverOperator}}
	vm := &Cluster{}
	req := upgradewire.ApplyRequest{Version: "v9.9.9", Source: upgradewire.SourceImages}
	if _, err := k8s.validateApply(req); err != nil {
		t.Fatalf("images on a Kubernetes-managed leader = %v", err)
	}
	if _, err := vm.validateApply(req); err == nil || !strings.Contains(err.Error(), "SB_UPGRADE_DRIVER=operator") {
		t.Fatalf("images on a VM leader = %v", err)
	}
	withFiles := req
	withFiles.Files = map[string]string{"sandboxd": strings.Repeat("a", 64)}
	if _, err := k8s.validateApply(withFiles); err == nil || !strings.Contains(err.Error(), "takes no files") {
		t.Fatalf("images with files = %v", err)
	}
	if _, err := k8s.validateApply(upgradewire.ApplyRequest{Version: "v9.9.9", Source: upgradewire.SourceRelease}); err == nil || !strings.Contains(err.Error(), "files is empty") {
		t.Fatalf("release without files = %v", err)
	}
}

// In an images rollout every operator-driven node is walked as before; a
// node that would stage files itself has none and is left to a person.
func TestRolloutDriverImagesRollout(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 2)
	g.nodes.nodes["s1"].stageErr = operatorDriven()
	g.nodes.nodes["w1"].stageErr = operatorDriven()
	g.start(func(r *RolloutRecord) {
		r.Source, r.Files, r.Hold, r.AllowDowntime = upgradewire.SourceImages, nil, true, true
	})
	for i := 0; i < 10 && g.host.rollout().Nodes["w1"].State != upgradewire.NodeUpgrading; i++ {
		g.driver.tick(context.Background())
	}
	r := g.host.rollout()
	if n := r.Nodes["w2"]; n.State != upgradewire.NodeManual || !strings.Contains(n.Error, "not operator-driven") {
		t.Fatalf("w2 (not operator-driven) = %+v", n)
	}
	if r.Nodes["w1"].State != upgradewire.NodeUpgrading || !r.Nodes["w1"].Operator {
		t.Fatalf("w1 = %+v", r.Nodes["w1"])
	}
	g.operatorSwap("w1", "v2")
	g.operatorSwap("w2", "v2")
	g.operatorSwap("s1", "v2")
	g.run(upgradewire.StateDone)
}

// --pause-after counts operator-driven workers like any other: the walk
// pauses once that many are done, starts no operator turn while paused,
// and goes on after a resume.
func TestRolloutDriverPauseAfterWithOperatorNodes(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 3)
	for _, id := range []string{"w1", "w2"} {
		g.nodes.nodes[id].stageErr = operatorDriven()
		g.nodes.nodes[id].applyErr = errors.New("the leader must not call an operator-driven node's upgrader")
	}
	g.start(func(r *RolloutRecord) { r.PauseAfter = 1; r.Batch = "1"; r.AllowDowntime = true; r.Hold = true })
	for i := 0; i < 50 && g.host.rollout().Nodes["w1"].State != upgradewire.NodeUpgrading; i++ {
		g.driver.tick(context.Background())
	}
	g.operatorSwap("w1", "v2")
	r := g.run(upgradewire.StatePaused)
	if r.workersDone() != 1 || r.Nodes["w1"].State != upgradewire.NodeDone {
		t.Fatalf("paused after %d workers: %s", r.workersDone(), describeNodes(r))
	}
	for i := 0; i < 5; i++ {
		g.driver.tick(context.Background())
	}
	if r := g.host.rollout(); r.Nodes["w2"].State == upgradewire.NodeUpgrading || r.Nodes["w3"].State == upgradewire.NodeUpgrading {
		t.Fatalf("an operator turn started while paused: %s", describeNodes(r))
	}
	if res, _ := g.host.event(context.Background(), RolloutCommand{Event: evResume, RolloutID: "r1"}); res.Rollout.State != upgradewire.StateRunning {
		t.Fatalf("resume = %+v", res.Verdict)
	}
	for i := 0; i < 50 && g.host.rollout().Nodes["w2"].State != upgradewire.NodeUpgrading; i++ {
		g.driver.tick(context.Background())
	}
	g.operatorSwap("w2", "v2")
	r = g.run(upgradewire.StateDone)
	if r.workersDone() != 3 || g.nodes.nodes["w1"].applyCalls+g.nodes.nodes["w2"].applyCalls != 0 {
		t.Fatalf("after resume %s", describeNodes(r))
	}
}

// The leader changes while the operator swaps a node: the new leader's
// driver starts with nothing in memory, reads the node's turn from the
// rollout record, keeps its deadline, never calls its upgrader, and
// finishes it once the node reports the target.
func TestRolloutDriverOperatorTurnSurvivesALeaderChange(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 2)
	g.nodes.nodes["w1"].stageErr = operatorDriven()
	g.nodes.nodes["w1"].applyErr = errors.New("the leader must not call an operator-driven node's upgrader")
	g.start(func(r *RolloutRecord) { r.Batch = "1"; r.AllowDowntime = true; r.Hold = true })
	for i := 0; i < 50 && g.host.rollout().Nodes["w1"].State != upgradewire.NodeUpgrading; i++ {
		g.driver.tick(context.Background())
	}
	before := g.host.rollout().Nodes["w1"]
	if before.State != upgradewire.NodeUpgrading || !before.Operator {
		t.Fatalf("w1 before the leader change = %+v", before)
	}

	// A new leader: a fresh driver over the same replicated record.
	d := newRolloutDriver(g.host, g.nodes, nil)
	d.inline = true
	d.applyResendAfter = time.Hour
	g.driver = d
	for i := 0; i < 5; i++ {
		g.driver.tick(context.Background())
	}
	after := g.host.rollout().Nodes["w1"]
	if after.State != upgradewire.NodeUpgrading || !after.Operator || after.DeadlineUnixNano != before.DeadlineUnixNano || after.Op != before.Op {
		t.Fatalf("w1 after the leader change = %+v, before %+v", after, before)
	}
	if r := g.host.rollout(); r.Nodes["w2"].State == upgradewire.NodeUpgrading {
		t.Fatalf("the new leader started w2 while w1 was still the operator's: %s", describeNodes(r))
	}
	g.operatorSwap("w1", "v2")
	r := g.run(upgradewire.StateDone)
	if r.Nodes["w1"].State != upgradewire.NodeDone || g.nodes.nodes["w1"].applyCalls != 0 {
		t.Fatalf("after the swap %s, %d apply calls", describeNodes(r), g.nodes.nodes["w1"].applyCalls)
	}
}

// The live host's gate: operator steps need every Raft server new enough
// to keep the operator flag in the rollout record.
func TestClusterRolloutHostOperatorStepsAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestCluster(t, "ldr-opgate", true, nil)
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	h := clusterRolloutHost{c: c}
	if !h.operatorStepsAllowed() {
		t.Fatal("a cluster of this build refused operator steps")
	}
	// A server gossip has never heard from reports version 0: too old.
	if err := c.raft.raft.AddNonvoter("old-server", "127.0.0.1:1", 0, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	if h.operatorStepsAllowed() {
		t.Fatal("operator steps allowed with an old server in the configuration")
	}
}
