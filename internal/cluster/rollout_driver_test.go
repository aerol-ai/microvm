package cluster

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
	"github.com/aerol-ai/microvm/pkg/upgradewire"
	"github.com/hashicorp/raft"
)

// Tests for the leader's rollout loop (rollout_driver.go) against a fake
// cluster and fake nodes. The fake host applies every write through a real
// placementFSM, so the transition tables decide exactly as in production.

type fakeRolloutHost struct {
	mu      sync.Mutex
	self    string
	leader  bool
	termV   uint64
	fsm     *placementFSM
	index   uint64
	memberM map[string]Member
	voterL  []string
	servers map[string]bool
	drain   map[string]bool
	drains  []string
	applied uint64
	clock   time.Time
}

func newFakeRolloutHost(fsm *placementFSM, self string) *fakeRolloutHost {
	return &fakeRolloutHost{self: self, leader: true, termV: 5, fsm: fsm, memberM: map[string]Member{},
		servers: map[string]bool{}, drain: map[string]bool{}, clock: time.Unix(1_000_000, 0)}
}

func (h *fakeRolloutHost) selfID() string { return h.self }
func (h *fakeRolloutHost) isLeader() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.leader
}
func (h *fakeRolloutHost) term() uint64            { return h.termV }
func (h *fakeRolloutHost) rollout() *RolloutRecord { r, _ := h.fsm.rolloutView(); return r }
func (h *fakeRolloutHost) members() map[string]Member {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]Member{}
	for k, v := range h.memberM {
		out[k] = v
	}
	return out
}
func (h *fakeRolloutHost) voters() []string            { return h.voterL }
func (h *fakeRolloutHost) isRaftServer(id string) bool { return h.servers[id] }
func (h *fakeRolloutHost) drained() map[string]bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]bool{}
	for k, v := range h.drain {
		if v {
			out[k] = true
		}
	}
	return out
}
func (h *fakeRolloutHost) appliedIndex() uint64 { return h.applied }
func (h *fakeRolloutHost) setDrain(_ context.Context, id string, d bool) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.drain[id] = d
	verb := "uncordon"
	if d {
		verb = "cordon"
	}
	h.drains = append(h.drains, verb+" "+id)
	return nil
}
func (h *fakeRolloutHost) apply(cmd command) (rolloutApplyResult, error) {
	h.mu.Lock()
	h.index++
	idx := h.index
	h.mu.Unlock()
	cmd.StampUnixNano = h.now().UnixNano()
	data, err := encodeCommand(cmd)
	if err != nil {
		return rolloutApplyResult{}, err
	}
	out := h.fsm.Apply(&raft.Log{Index: idx, Data: data})
	if e, ok := out.(error); ok {
		return rolloutApplyResult{}, e
	}
	res, _ := out.(rolloutApplyResult)
	return res, nil
}
func (h *fakeRolloutHost) nodeUpdate(_ context.Context, u RolloutNodeUpdate) (rolloutApplyResult, error) {
	if !h.isLeader() {
		return rolloutApplyResult{}, ErrNotLeader
	}
	return h.apply(command{Op: opRolloutNode, RolloutNode: &u})
}
func (h *fakeRolloutHost) event(_ context.Context, rc RolloutCommand) (rolloutApplyResult, error) {
	if !h.isLeader() {
		return rolloutApplyResult{}, ErrNotLeader
	}
	return h.apply(command{Op: opRolloutCommand, RolloutCmd: &rc})
}
func (h *fakeRolloutHost) finalizeTarget(r *RolloutRecord) (ActiveVersion, error) {
	return ActiveVersion{FV: 13, Release: r.TargetVersion}, nil
}
func (h *fakeRolloutHost) now() time.Time {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.clock
}
func (h *fakeRolloutHost) advance(d time.Duration) {
	h.mu.Lock()
	h.clock = h.clock.Add(d)
	h.mu.Unlock()
}
func (h *fakeRolloutHost) setVersion(id, v string) {
	h.mu.Lock()
	m := h.memberM[id]
	m.Version = v
	h.memberM[id] = m
	h.mu.Unlock()
}
func (h *fakeRolloutHost) setAlive(id string, alive bool) {
	h.mu.Lock()
	m := h.memberM[id]
	m.Alive = alive
	h.memberM[id] = m
	h.mu.Unlock()
}

// fakeNode is one node's behaviour.
type fakeNode struct {
	version     string
	stageErr    error
	applyErr    error
	opFails     bool // the upgrader fails and reverts
	neverHealth bool // the new build never answers
	finalizeErr error
	op          string
	opVersion   string
	applies     int
	stages      int
	finalizes   int
}

// fakeNodes is rolloutNodeClient over fakeNodes; an apply "restarts" the
// node at once: the next Status reports the new version and gossip shows it.
type fakeNodes struct {
	mu         sync.Mutex
	host       *fakeRolloutHost
	nodes      map[string]*fakeNode
	order      []string
	transfers  []string
	onTransfer func(to string)
	statusErr  error
}

func (f *fakeNodes) node(id string) *fakeNode {
	n := f.nodes[id]
	if n == nil {
		n = &fakeNode{}
		f.nodes[id] = n
	}
	return n
}

func (f *fakeNodes) Step(_ context.Context, m Member, req UpgradeStepRequest) (UpgradeStepResponse, error) {
	f.mu.Lock()
	n := f.node(m.NodeID)
	resp := UpgradeStepResponse{NodeID: m.NodeID, Step: req.Step, Version: n.version, Arch: "amd64"}
	switch req.Step {
	case UpgradeStepStage:
		n.stages++
		err := n.stageErr
		resp.State = UpgradeNodeStaged
		resp.Installed = map[string]string{"sandboxd": "prev-" + n.version, "toolboxd": "prevt-" + n.version}
		f.mu.Unlock()
		return resp, err
	case UpgradeStepApply:
		if n.applyErr != nil {
			err := n.applyErr
			f.mu.Unlock()
			return resp, err
		}
		if n.op == req.Op {
			resp.State = UpgradeNodeStarted
			f.mu.Unlock()
			return resp, nil
		}
		n.applies++
		n.op, n.opVersion = req.Op, req.Version
		f.order = append(f.order, req.Direction+":"+m.NodeID)
		resp.State, resp.Op = UpgradeNodeStarted, req.Op
		upgraded := !n.opFails && !n.neverHealth
		if upgraded {
			n.version = req.Version
		}
		f.mu.Unlock()
		if upgraded {
			f.host.setVersion(m.NodeID, req.Version)
		}
		return resp, nil
	default:
		n.finalizes++
		err := n.finalizeErr
		resp.State = UpgradeNodeMigrated
		f.mu.Unlock()
		return resp, err
	}
}

func (f *fakeNodes) Status(_ context.Context, m Member, op string) (UpgradeNodeStatus, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.statusErr != nil {
		return UpgradeNodeStatus{}, f.statusErr
	}
	n := f.node(m.NodeID)
	st := UpgradeNodeStatus{NodeID: m.NodeID, Version: n.version, AppliedIndex: f.host.appliedIndex(), Op: op}
	if op != "" && op == n.op {
		st.OpFound, st.OpVersion = true, n.opVersion
		st.OpPhase = string(nodeupgrade.PhaseDone)
		if n.opFails {
			st.OpPhase, st.OpError = string(nodeupgrade.PhaseFailed), "health check failed"
		}
		if n.neverHealth {
			st.OpPhase = string(nodeupgrade.PhaseStarting)
		}
	}
	return st, nil
}

func (f *fakeNodes) TransferLeadership(_ context.Context, to Member) error {
	f.mu.Lock()
	f.transfers = append(f.transfers, to.NodeID)
	cb := f.onTransfer
	f.mu.Unlock()
	if cb != nil {
		cb(to.NodeID)
	}
	return nil
}

func (f *fakeNodes) applyOrder() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.order...)
}

// rolloutRig is a cluster of servers, ingress nodes and workers on v1.
type rolloutRig struct {
	t      *testing.T
	fsm    *placementFSM
	host   *fakeRolloutHost
	nodes  *fakeNodes
	driver *rolloutDriver
}

func newRolloutRig(t *testing.T, servers, ingress, workers int) *rolloutRig {
	fsm := newPlacementFSM()
	host := newFakeRolloutHost(fsm, "s1")
	nodes := &fakeNodes{host: host, nodes: map[string]*fakeNode{}}
	add := func(id, role string, server bool) {
		host.memberM[id] = Member{NodeID: id, Role: role, Alive: true, Version: "v1", Arch: "amd64", InternalURL: "https://" + id}
		nodes.nodes[id] = &fakeNode{version: "v1"}
		if server {
			host.servers[id] = true
			host.voterL = append(host.voterL, id)
		}
	}
	for i := 1; i <= servers; i++ {
		add(fmt.Sprintf("s%d", i), "server", true)
	}
	for i := 1; i <= ingress; i++ {
		add(fmt.Sprintf("i%d", i), "ingress", false)
	}
	for i := 1; i <= workers; i++ {
		add(fmt.Sprintf("w%d", i), "worker", false)
	}
	d := newRolloutDriver(host, nodes, nil)
	d.inline = true
	d.applyResendAfter = time.Hour
	return &rolloutRig{t: t, fsm: fsm, host: host, nodes: nodes, driver: d}
}

// start writes a rollout to v2 the way ApplyRollout builds it.
func (g *rolloutRig) start(edit func(r *RolloutRecord)) *RolloutRecord {
	g.t.Helper()
	r := &RolloutRecord{
		ID: "r1", TargetVersion: "v2", PreviousVersion: "v1", Source: upgradewire.SourceUpload, Caller: "pat:op", Batch: "10%",
		NodeTimeoutNanos: int64(10 * time.Minute), AllowUnversioned: true,
		Files: map[string]string{"sandboxd_linux_amd64": strings.Repeat("a", 64), "toolboxd_linux_amd64": strings.Repeat("b", 64)},
		Nodes: map[string]*RolloutNodeRecord{},
	}
	if edit != nil {
		edit(r)
	}
	var members []rolloutMember
	for _, id := range sortedMemberIDs(g.host.memberM) {
		m := g.host.memberM[id]
		members = append(members, rolloutMember{Member: m, tier: rolloutTierOf(m, g.host.servers[id])})
	}
	if err := orderRolloutNodes(r, members, g.host.self, len(g.host.voterL) == 1); err != nil {
		g.t.Fatal(err)
	}
	for id, n := range r.Nodes {
		n.WasCordoned = g.host.drain[id]
	}
	res, err := g.host.event(context.Background(), RolloutCommand{Event: evApply, New: r, Target: r.TargetVersion})
	if err != nil || res.Verdict.Outcome != outcomeNew {
		g.t.Fatalf("start = %+v %v", res, err)
	}
	return res.Rollout
}

// run ticks until the rollout reaches one of states, or fails the test.
func (g *rolloutRig) run(states ...string) *RolloutRecord {
	g.t.Helper()
	for i := 0; i < 200; i++ {
		g.driver.tick(context.Background())
		r := g.host.rollout()
		if r != nil && containsState(states, r.State) {
			return r
		}
	}
	r := g.host.rollout()
	g.t.Fatalf("rollout never reached %v: %s %s", states, r.State, describeNodes(r))
	return nil
}

func describeNodes(r *RolloutRecord) string {
	var parts []string
	for _, n := range r.sortedNodes() {
		parts = append(parts, fmt.Sprintf("%s=%s(%s)", n.NodeID, n.State, n.Error))
	}
	return strings.Join(parts, " ")
}

func TestRolloutDriverFullUpgradeWithLeaderHandOff(t *testing.T) {
	g := newRolloutRig(t, 3, 1, 5)
	g.host.drain["w3"] = true // cordoned by the operator before the rollout
	g.start(func(r *RolloutRecord) { r.Batch = "2"; r.Hold = true })
	// s1 is this leader: when only it is left among the servers it hands
	// off, and the new leader (s2, already upgraded) finishes the job.
	g.nodes.onTransfer = func(to string) {
		g.host.mu.Lock()
		g.host.leader = false
		g.host.mu.Unlock()
	}
	r := g.run(upgradewire.StateRunning)
	g.run(upgradewire.StateRunning)
	for i := 0; i < 30 && len(g.nodes.transfers) == 0; i++ {
		g.driver.tick(context.Background())
	}
	if len(g.nodes.transfers) != 1 || g.nodes.transfers[0] != "s2" {
		t.Fatalf("transfers = %v, want one hand-off to an upgraded server", g.nodes.transfers)
	}
	// The new leader resumes from the record alone.
	newHost := newFakeRolloutHost(g.fsm, "s2")
	newHost.memberM, newHost.voterL, newHost.servers, newHost.drain, newHost.index = g.host.memberM, g.host.voterL, g.host.servers, g.host.drain, g.host.index
	newHost.clock = g.host.clock
	g.nodes.host = newHost
	g.host = newHost
	g.driver = newRolloutDriver(newHost, g.nodes, nil)
	g.driver.inline = true
	r = g.run(upgradewire.StateDone)
	if describeNodes(r) == "" || len(r.nodesIn(upgradewire.NodeDone)) != 9 {
		t.Fatalf("done with %s", describeNodes(r))
	}
	want := []string{"upgrade:s2", "upgrade:s3", "upgrade:s1", "upgrade:i1", "upgrade:w1", "upgrade:w2", "upgrade:w3", "upgrade:w4", "upgrade:w5"}
	if got := g.nodes.applyOrder(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("apply order = %v\nwant %v", got, want)
	}
	for id, n := range g.nodes.nodes {
		if n.applies != 1 || n.stages != 1 {
			t.Fatalf("%s: %d applies, %d stages, want one each", id, n.applies, n.stages)
		}
	}
	// Batches of 2; every worker cordoned before its restart, and given its
	// own mark back after: w3 stays cordoned.
	if r.Nodes["w1"].Batch != 1 || r.Nodes["w3"].Batch != 2 || r.Nodes["w5"].Batch != 3 {
		t.Fatalf("batches %d %d %d", r.Nodes["w1"].Batch, r.Nodes["w3"].Batch, r.Nodes["w5"].Batch)
	}
	if !g.host.drain["w3"] || g.host.drain["w1"] || g.host.drain["w5"] {
		t.Fatalf("cordon marks after the rollout = %v", g.host.drain)
	}
	if r.PrevFiles["sandboxd_linux_amd64"] != "prev-v1" {
		t.Fatalf("prev files = %v", r.PrevFiles)
	}
	// Held: done stays done until finalize.
	for i := 0; i < 3; i++ {
		g.driver.tick(context.Background())
	}
	if g.host.rollout().State != upgradewire.StateDone {
		t.Fatal("a held rollout finalized by itself")
	}
}

func TestRolloutDriverWorkerCordonedBeforeRestart(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 2)
	g.host.voterL = []string{"s1", "x", "y"} // three voters, so s1 is not alone
	g.host.memberM["x"] = Member{NodeID: "x", Alive: true, Role: "server", Version: "v2"}
	g.host.memberM["y"] = Member{NodeID: "y", Alive: true, Role: "server", Version: "v2"}
	g.host.servers["x"], g.host.servers["y"] = true, true
	g.start(func(r *RolloutRecord) { r.Batch = "100%" })
	g.nodes.onTransfer = func(to string) { g.host.self = to }
	g.run(upgradewire.StateRunning)
	for i := 0; i < 20 && g.nodes.nodes["w1"].applies == 0; i++ {
		g.driver.tick(context.Background())
	}
	got := strings.Join(g.host.drains, ",")
	if !strings.Contains(got, "cordon w1") || !strings.Contains(got, "cordon w2") {
		t.Fatalf("drains = %s, want the batch cordoned", got)
	}
}

func TestRolloutDriverAutoFinalize(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 2)
	g.start(func(r *RolloutRecord) { r.AllowDowntime = true })
	r := g.run(upgradewire.StateFinalized)
	if g.fsm.activeFVValue() != 13 {
		t.Fatalf("active fv = %d", g.fsm.activeFVValue())
	}
	for id, n := range g.nodes.nodes {
		if n.finalizes != 1 || !r.Nodes[id].Migrated {
			t.Fatalf("%s finalized %d times, migrated %v", id, n.finalizes, r.Nodes[id].Migrated)
		}
	}
	// One voter: ingress and workers first, the server last (eng D8).
	if got := g.nodes.applyOrder(); got[len(got)-1] != "upgrade:s1" {
		t.Fatalf("one-voter order = %v", got)
	}
}

func TestRolloutDriverStageFailureStopsBeforeAnyRestart(t *testing.T) {
	g := newRolloutRig(t, 3, 1, 3)
	g.nodes.nodes["w2"].stageErr = &UpgradeStepError{Status: http.StatusUnprocessableEntity, Reason: "not enough free space"}
	g.start(nil)
	r := g.run(upgradewire.StateFailed)
	if r.Nodes["w2"].State != upgradewire.NodeFailed || !strings.Contains(r.Error, "not enough free space") {
		t.Fatalf("failed rollout = %+v %s", r.Error, describeNodes(r))
	}
	if got := g.nodes.applyOrder(); len(got) != 0 {
		t.Fatalf("nodes restarted after a stage failure: %v", got)
	}
	// Servers staged first: every server's stage ran before any worker's.
	if g.nodes.nodes["s1"].stages != 1 || g.nodes.nodes["w1"].stages > 1 {
		t.Fatal("stage counts")
	}
	// Fixed, apply again: back to staging, and it finishes.
	g.nodes.nodes["w2"].stageErr = nil
	res, _ := g.host.event(context.Background(), RolloutCommand{Event: evApply, Target: "v2"})
	if res.Verdict.Outcome != outcomeRestage {
		t.Fatalf("apply again = %+v", res.Verdict)
	}
	g.nodes.onTransfer = func(to string) { g.host.self = to }
	g.run(upgradewire.StateFinalized)
}

func TestRolloutDriverPauseAfterAndResume(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 5)
	g.start(func(r *RolloutRecord) { r.PauseAfter = 2; r.Batch = "3"; r.AllowDowntime = true; r.Hold = true })
	r := g.run(upgradewire.StatePaused)
	if r.workersDone() != 2 || r.Nodes["w1"].Batch != 1 || r.Nodes["w3"].Batch != 2 {
		t.Fatalf("paused after %d workers, batches %s", r.workersDone(), describeNodes(r))
	}
	for i := 0; i < 5; i++ {
		g.driver.tick(context.Background())
	}
	if r := g.host.rollout(); r.workersDone() != 2 {
		t.Fatalf("a paused rollout kept going: %s", describeNodes(r))
	}
	if res, _ := g.host.event(context.Background(), RolloutCommand{Event: evResume, RolloutID: "r1"}); res.Rollout.State != upgradewire.StateRunning {
		t.Fatalf("resume = %+v", res.Verdict)
	}
	r = g.run(upgradewire.StateDone)
	if r.workersDone() != 5 || !r.Paused {
		t.Fatalf("after resume %s", describeNodes(r))
	}
}

func TestRolloutDriverStopFinishesInFlightOnly(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 2)
	g.nodes.nodes["w1"].neverHealth = true
	g.start(func(r *RolloutRecord) { r.AllowDowntime = true; r.Batch = "1" })
	g.run(upgradewire.StateRunning)
	for i := 0; i < 10 && g.nodes.nodes["w1"].applies == 0; i++ {
		g.driver.tick(context.Background())
	}
	g.host.event(context.Background(), RolloutCommand{Event: evStop, RolloutID: "r1"})
	g.nodes.mu.Lock()
	g.nodes.nodes["w1"].neverHealth = false
	g.nodes.nodes["w1"].version = "v2"
	g.nodes.mu.Unlock()
	g.host.setVersion("w1", "v2")
	for i := 0; i < 5; i++ {
		g.driver.tick(context.Background())
	}
	r := g.host.rollout()
	if r.State != upgradewire.StateStopped || r.Nodes["w1"].State != upgradewire.NodeDone || g.nodes.nodes["w2"].applies != 0 {
		t.Fatalf("stopped rollout: %s, w2 applies %d", describeNodes(r), g.nodes.nodes["w2"].applies)
	}
}

func TestRolloutDriverDownWorkerSkippedThenCaughtUp(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 3)
	g.host.setAlive("w2", false)
	g.start(func(r *RolloutRecord) { r.AllowDowntime = true })
	r := g.run(upgradewire.StateDone)
	if r.Nodes["w2"].State != upgradewire.NodeSkipped || !g.host.drain["w2"] {
		t.Fatalf("down worker: %s, cordoned %v", describeNodes(r), g.host.drain["w2"])
	}
	// Not finalized while it is skipped.
	for i := 0; i < 3; i++ {
		g.driver.tick(context.Background())
	}
	if g.host.rollout().State != upgradewire.StateDone {
		t.Fatal("finalized with a skipped node")
	}
	if v := decideRollout(g.host.rollout(), rolloutEvent{Kind: evFinalize}); v.Code != upgradewire.ErrCodeSkippedNodes {
		t.Fatalf("finalize = %+v", v)
	}
	// It comes back: staged, upgraded, uncordoned, then auto-finalize.
	g.host.setAlive("w2", true)
	r = g.run(upgradewire.StateFinalized)
	if g.nodes.nodes["w2"].applies != 1 || g.host.drain["w2"] {
		t.Fatalf("caught up %d times, cordoned %v", g.nodes.nodes["w2"].applies, g.host.drain["w2"])
	}
	_ = r
}

func TestRolloutDriverQuorumBlocksServerRestart(t *testing.T) {
	g := newRolloutRig(t, 3, 0, 1)
	g.host.setAlive("s3", false)
	g.start(nil)
	r := g.run(upgradewire.StateFailed)
	if !strings.Contains(r.Error, "s3") || r.Nodes["s2"].State != upgradewire.NodeFailed || r.Nodes["s3"].State != upgradewire.NodeSkipped {
		t.Fatalf("quorum failure: %q %s", r.Error, describeNodes(r))
	}
	if got := g.nodes.applyOrder(); len(got) != 0 {
		t.Fatalf("a server restarted without a majority: %v", got)
	}
}

func TestRolloutDriverNodeTimeoutFailsRollout(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 1)
	g.nodes.nodes["w1"].neverHealth = true
	g.start(func(r *RolloutRecord) { r.AllowDowntime = true; r.NodeTimeoutNanos = int64(time.Minute) })
	g.run(upgradewire.StateRunning)
	for i := 0; i < 10 && g.nodes.nodes["w1"].applies == 0; i++ {
		g.driver.tick(context.Background())
	}
	g.driver.tick(context.Background())
	if g.host.rollout().State != upgradewire.StateRunning {
		t.Fatal("failed before the deadline")
	}
	g.host.advance(2 * time.Minute)
	r := g.run(upgradewire.StateFailed)
	if !strings.Contains(r.Nodes["w1"].Error, "within 1m0s") {
		t.Fatalf("timeout error = %q", r.Nodes["w1"].Error)
	}
}

func TestRolloutDriverUpgraderFailureAndRollback(t *testing.T) {
	g := newRolloutRig(t, 1, 1, 2)
	g.nodes.nodes["w2"].opFails = true
	g.start(func(r *RolloutRecord) { r.AllowDowntime = true; r.Batch = "1" })
	r := g.run(upgradewire.StateFailed)
	if r.Nodes["w2"].State != upgradewire.NodeFailed || !strings.Contains(r.Nodes["w2"].Error, "put the previous files back") {
		t.Fatalf("w2 = %+v", r.Nodes["w2"])
	}
	if g.host.drain["w2"] {
		t.Fatal("a failed node stays cordoned")
	}
	res, _ := g.host.event(context.Background(), RolloutCommand{Event: evRollback, RolloutID: "r1"})
	if res.Rollout.State != upgradewire.StateRollingBack {
		t.Fatalf("rollback = %+v", res.Verdict)
	}
	r = g.run(upgradewire.StateRolledBack)
	got := g.nodes.applyOrder()
	// Workers first, then ingress; nodes still on v1 need no restart.
	back := []string{}
	for _, s := range got {
		if strings.HasPrefix(s, "rollback:") {
			back = append(back, s)
		}
	}
	if strings.Join(back, ",") != "rollback:w1,rollback:i1" {
		t.Fatalf("rollback restarts = %v (all %v)", back, got)
	}
	for _, n := range r.sortedNodes() {
		if n.State != upgradewire.NodeDone {
			t.Fatalf("after rollback %s", describeNodes(r))
		}
	}
	for id, m := range g.host.memberM {
		if m.Version != "v1" {
			t.Fatalf("%s runs %s after the rollback", id, m.Version)
		}
	}
}

func TestRolloutDriverRollbackOrderReverse(t *testing.T) {
	g := newRolloutRig(t, 1, 1, 2)
	g.start(func(r *RolloutRecord) { r.AllowDowntime = true; r.Hold = true })
	g.run(upgradewire.StateDone)
	g.host.event(context.Background(), RolloutCommand{Event: evRollback, RolloutID: "r1"})
	g.run(upgradewire.StateRolledBack)
	var back []string
	for _, s := range g.nodes.applyOrder() {
		if strings.HasPrefix(s, "rollback:") {
			back = append(back, strings.TrimPrefix(s, "rollback:"))
		}
	}
	if strings.Join(back, ",") != "w1,w2,i1,s1" {
		t.Fatalf("rollback order = %v, want workers, ingress, then the server", back)
	}
}

func TestRolloutDriverRemoteUpgradeOffIsManual(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 2)
	g.nodes.nodes["w1"].stageErr = &UpgradeStepError{Status: http.StatusConflict, Code: upgradewire.ErrCodeRemoteUpgradeDisabled, Reason: "off"}
	g.start(func(r *RolloutRecord) { r.AllowDowntime = true; r.Hold = true })
	g.run(upgradewire.StateRunning)
	for i := 0; i < 10; i++ {
		g.driver.tick(context.Background())
	}
	r := g.host.rollout()
	n := r.Nodes["w1"]
	if n.State != upgradewire.NodeManual || !strings.Contains(n.ManualCommand, "sudo sandboxd upgrade node v2") || !strings.Contains(n.ManualCommand, "--sha256") {
		t.Fatalf("manual node = %+v", n)
	}
	if r.State == upgradewire.StateDone {
		t.Fatal("done while a node is manual")
	}
	// The operator runs the command: the node reports v2 and is done.
	g.host.setVersion("w1", "v2")
	g.run(upgradewire.StateDone)
}

func TestRolloutDriverNewLeaderNeverUpgradesTwice(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 1)
	g.nodes.nodes["w1"].neverHealth = true
	g.start(func(r *RolloutRecord) { r.AllowDowntime = true })
	g.run(upgradewire.StateRunning)
	for i := 0; i < 10 && g.nodes.nodes["w1"].applies == 0; i++ {
		g.driver.tick(context.Background())
	}
	// A new leader with no memory of the call: the node reports its op, so
	// it is followed, never started again.
	d2 := newRolloutDriver(g.host, g.nodes, nil)
	d2.inline, d2.applyResendAfter = true, 0
	for i := 0; i < 5; i++ {
		d2.tick(context.Background())
	}
	if g.nodes.nodes["w1"].applies != 1 {
		t.Fatalf("w1 applies = %d", g.nodes.nodes["w1"].applies)
	}
	// An op that never reached the node (the old leader died between the
	// record and the call) is sent again, with the same op ID.
	g.nodes.mu.Lock()
	g.nodes.nodes["w1"].op = ""
	g.nodes.nodes["w1"].neverHealth = false
	g.nodes.mu.Unlock()
	g.host.advance(time.Second)
	d2.tick(context.Background())
	g.driver = d2
	g.run(upgradewire.StateFinalized)
	if g.nodes.nodes["w1"].applies != 2 || g.nodes.nodes["w1"].op != rolloutOpID(g.host.rollout()) {
		t.Fatalf("resent apply: %+v", g.nodes.nodes["w1"])
	}
}

func TestRolloutDriverAdoptsJoinedNode(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 1)
	g.start(func(r *RolloutRecord) { r.AllowDowntime = true; r.Hold = true })
	g.host.memberM["w7"] = Member{NodeID: "w7", Role: "worker", Alive: true, Version: "v1"}
	g.host.memberM["w8"] = Member{NodeID: "w8", Role: "worker", Alive: true, Version: "v2"}
	g.nodes.nodes["w7"] = &fakeNode{version: "v1"}
	g.nodes.nodes["w8"] = &fakeNode{version: "v2"}
	g.driver.tick(context.Background())
	r := g.host.rollout()
	if r.Nodes["w7"] == nil || r.Nodes["w7"].State != upgradewire.NodePending || r.Nodes["w8"].State != upgradewire.NodeDone || !g.host.drain["w7"] {
		t.Fatalf("adopted: %s", describeNodes(r))
	}
	r = g.run(upgradewire.StateDone)
	if g.nodes.nodes["w7"].applies != 1 || g.nodes.nodes["w8"].applies != 0 || g.host.drain["w7"] {
		t.Fatalf("joined nodes: %s", describeNodes(r))
	}
}

func TestRolloutDriverFinalizeMigrationFailure(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 1)
	g.nodes.nodes["w1"].finalizeErr = &UpgradeStepError{Status: http.StatusInternalServerError, Reason: "disk I/O"}
	g.start(func(r *RolloutRecord) { r.AllowDowntime = true })
	g.run(upgradewire.StateFinalizing)
	for i := 0; i < 5; i++ {
		g.driver.tick(context.Background())
	}
	r := g.host.rollout()
	if r.State != upgradewire.StateFinalizing || !strings.Contains(r.Nodes["w1"].Error, "disk I/O") || !g.host.drain["w1"] {
		t.Fatalf("finalize failure: %s cordon %v", describeNodes(r), g.host.drain["w1"])
	}
	g.nodes.nodes["w1"].finalizeErr = nil
	g.run(upgradewire.StateFinalized)
}

func TestRolloutDriverStagingTimeout(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 1)
	g.nodes.nodes["w1"].stageErr = errors.New("connection refused")
	g.start(func(r *RolloutRecord) { r.AllowDowntime = true; r.NodeTimeoutNanos = int64(time.Minute) })
	for i := 0; i < 5; i++ {
		g.driver.tick(context.Background())
	}
	if g.host.rollout().State != upgradewire.StateStaging {
		t.Fatal("a retryable stage error failed staging early")
	}
	g.host.advance(2 * time.Minute)
	r := g.run(upgradewire.StateFailed)
	if !strings.Contains(r.Nodes["w1"].Error, "did not stage") {
		t.Fatalf("w1 = %+v", r.Nodes["w1"])
	}
}

func TestRolloutDriverIdleAndNotLeader(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 1)
	g.driver.tick(context.Background()) // no rollout: nothing
	g.start(nil)
	g.host.leader = false
	g.driver.tick(context.Background())
	if g.nodes.nodes["s1"].stages != 0 {
		t.Fatal("a follower drove the rollout")
	}
}

func TestRolloutDriverHelpers(t *testing.T) {
	if !stepRetryable(errors.New("dial tcp")) || stepRetryable(nil) || stepRetryable(&UpgradeStepError{Status: 422}) ||
		!stepRetryable(&UpgradeStepError{Status: 503}) || !stepRetryable(&UpgradeStepError{Code: upgradeCodeNotLeader}) {
		t.Fatal("stepRetryable")
	}
	if stepCode(errors.New("x")) != "" || stepCode(&UpgradeStepError{Code: "c"}) != "c" {
		t.Fatal("stepCode")
	}
	if prevFiles(nil, "amd64", nil) != nil || prevFiles(map[string]string{"a": "b"}, "", nil) != nil {
		t.Fatal("prevFiles")
	}
	// Only binaries the target replaces count for a rollback.
	got := prevFiles(map[string]string{"sandboxd": "s", "toolboxd": "t", "caddy": "c"}, "arm64",
		map[string]string{"sandboxd_linux_arm64": "x", "toolboxd": "y", "release.json": "z"})
	if len(got) != 2 || got["sandboxd_linux_arm64"] != "s" || got["toolboxd_linux_arm64"] != "t" || got["caddy_linux_arm64"] != "" {
		t.Fatalf("prevFiles = %v", got)
	}
	if prevFiles(map[string]string{"caddy": "c"}, "amd64", map[string]string{"sandboxd": "x"}) != nil {
		t.Fatal("prevFiles kept a binary the target does not replace")
	}
	if !majorityUp([]string{"a", "b", "c"}, "b", "a", map[string]Member{"c": {Alive: true}}) ||
		majorityUp([]string{"a", "b", "c"}, "b", "a", map[string]Member{}) {
		t.Fatal("majorityUp")
	}
	r := &RolloutRecord{ID: "r", Attempt: 2, Direction: upgradewire.DirectionRollback}
	if rolloutOpID(r) != "r-b2" || targetOf(&RolloutRecord{TargetVersion: "t", PreviousVersion: "p", Direction: upgradewire.DirectionRollback}) != "p" {
		t.Fatal("op id / target")
	}
	ids := sortedMemberIDs(map[string]Member{"b": {}, "a": {}})
	if !sort.StringsAreSorted(ids) {
		t.Fatal("sorted member ids")
	}
	d := newRolloutDriver(nil, nil, nil)
	d.logf("x")
	d.warnf("x")
	if !d.claim("n") || d.claim("n") || !d.busy("n") {
		t.Fatal("claim")
	}
	d.release("n")
}

// deleteNode writes the deny record `aerolvm delete node` writes, and the
// node leaves gossip.
func (g *rolloutRig) deleteNode(id string) {
	g.t.Helper()
	g.host.mu.Lock()
	g.host.index++
	idx := g.host.index
	delete(g.host.memberM, id)
	g.host.mu.Unlock()
	data, err := encodeCommand(command{Op: opDenyNode, StampUnixNano: g.host.now().UnixNano(), NodeDeny: &NodeDenyRecord{NodeID: id}})
	if err != nil {
		g.t.Fatal(err)
	}
	if e, ok := g.fsm.Apply(&raft.Log{Index: idx, Data: data}).(error); ok {
		g.t.Fatal(e)
	}
}

// R3: the finalize refusal tells the operator to delete a skipped node;
// once it is deleted, the rollout finalizes by itself.
func TestRolloutDriverDeletedSkippedNodeLetsFinalizeRun(t *testing.T) {
	g := newRolloutRig(t, 1, 0, 3)
	g.host.setAlive("w2", false)
	g.start(func(r *RolloutRecord) { r.AllowDowntime = true })
	r := g.run(upgradewire.StateDone)
	if r.Nodes["w2"].State != upgradewire.NodeSkipped {
		t.Fatalf("w2 = %s", describeNodes(r))
	}
	g.deleteNode("w2")
	r = g.run(upgradewire.StateFinalized)
	if r.Nodes["w2"] != nil {
		t.Fatalf("finalized with a deleted node: %s", describeNodes(r))
	}
}
