package cluster

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeSnapshotMoves is a worker with the snapshot half, recording the
// leader's calls in order.
type fakeSnapshotMoves struct {
	fakeMoves
	mu        sync.Mutex
	calls     []string
	importErr error
}

func (f *fakeSnapshotMoves) note(s string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, s)
}

func (f *fakeSnapshotMoves) ReleaseForSnapshotMove(_ context.Context, id, target string) string {
	f.note("release " + id + " for " + target)
	return "released"
}

func (f *fakeSnapshotMoves) ImportMove(_ context.Context, id, source string) error {
	f.note("import " + id + " from " + source)
	return f.importErr
}

func (f *fakeSnapshotMoves) DropMove(_ context.Context, id string) error {
	f.note("drop " + id)
	return nil
}

func (f *fakeSnapshotMoves) StartMoved(_ context.Context, id string, rc *MoveRecreate) error {
	if rc == nil {
		f.note("start " + id + " without a spec")
		return nil
	}
	f.note("start " + id + " from " + rc.Spec.Image)
	return nil
}

func placeFirecracker(t *testing.T, c *Cluster, id, owner string, spec models.CreateSandboxRequest) {
	t.Helper()
	spec.Runtime = models.RuntimeFirecracker
	raw, err := encodeCommand(command{Op: opPlace, SandboxID: id, OwnerNodeID: owner, OwnerAPIURL: "http://" + owner, IncarnationID: "inc-" + id, Spec: &spec})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.raft.raft.Apply(raw, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
}

// A Firecracker sandbox without the recreate policy moves by snapshot:
// release on the source naming the target, import on the target from the
// source, the swap, then a start on the target, in that order.
func TestEvacuateNodeMovesAFirecrackerSandboxBySnapshot(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestClusterWithCfg(t, "ldr-snap", true, nil, func(cfg *config.Config) { cfg.NodeRole = config.NodeRoleMixed })
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	source, target := &fakeSnapshotMoves{}, &fakeSnapshotMoves{}
	c.AttachMoveHandler(source)
	c.moves.mu.Lock()
	c.moves.peers = map[string]MoveHandler{"wkr-b": target}
	c.moves.mu.Unlock()
	room := capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16384, CPUBudget: 8, MemoryBudgetMB: 16384, CanAdmit: true,
		SupportedRuntimes: []string{models.RuntimeFirecracker}}
	self, _ := c.gossip.lookupMember(c.nodeID)
	self.Role = config.NodeRoleMixed
	seedGossipView(t, c, []Member{self, {NodeID: "wkr-b", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://wkr-b", Capacity: room, Arch: self.Arch, Version: self.Version}})
	placeFirecracker(t, c, "sb-vm", c.nodeID, models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 128})
	// External-storage mounts: not moved by snapshot (notice, then stop).
	placeFirecracker(t, c, "sb-mounted", c.nodeID, models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 128,
		Mounts: []models.MountSpec{{Type: "s3"}}})
	applyDrain(t, c, c.nodeID)

	res, err := c.EvacuateNode(context.Background(), c.nodeID, EvacuateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Moved, ",") != "sb-vm" || res.Remaining != 1 || res.RemainingMovable != 0 {
		t.Fatalf("pass = %+v", res)
	}
	if owner, err := c.OwnerOf("sb-vm"); err != nil || owner.NodeID != "wkr-b" {
		t.Fatalf("sb-vm owner = %+v %v", owner, err)
	}
	if got := strings.Join(source.calls, "; "); got != "release sb-vm for wkr-b" {
		t.Fatalf("source calls: %s", got)
	}
	if got := strings.Join(target.calls, "; "); got != "import sb-vm from "+c.nodeID+"; start sb-vm from alpine" {
		t.Fatalf("target calls: %s", got)
	}
}

// A gVisor sandbox moves with its memory (C21) the way a Firecracker one
// does, between workers that both report CheckpointMovesLabel. From a
// worker without it, its gVisor sandboxes are not movable: they count as
// the decommission's to stop, as before.
func TestEvacuateNodeMovesAGvisorSandboxWithItsMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestClusterWithCfg(t, "ldr-ckpt", true, nil, func(cfg *config.Config) { cfg.NodeRole = config.NodeRoleMixed })
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	source, target := &fakeSnapshotMoves{}, &fakeSnapshotMoves{}
	c.AttachMoveHandler(source)
	c.moves.mu.Lock()
	c.moves.peers = map[string]MoveHandler{"wkr-b": target}
	c.moves.mu.Unlock()
	moves := map[string]string{CheckpointMovesLabel: "true"}
	room := capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16384, CPUBudget: 8, MemoryBudgetMB: 16384, CanAdmit: true,
		SupportedRuntimes: []string{models.RuntimeGvisor}}
	self, _ := c.gossip.lookupMember(c.nodeID)
	self.Role = config.NodeRoleMixed
	self.Capacity = room
	worker := Member{NodeID: "wkr-b", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://wkr-b", Capacity: room, Arch: self.Arch, Version: self.Version}
	// The label rides the capacity heartbeats only, as in production:
	// gossip members carry none (p5-gmove-1 never moved its sandbox).
	labelled := func(ms ...Member) []Member {
		out := make([]Member, len(ms))
		for i, m := range ms {
			m.Capacity.Labels = moves
			out[i] = m
		}
		return out
	}
	seedGossipView(t, c, []Member{self, worker})
	seedCapacityHeartbeats(c, labelled(self, worker))
	gvisor := models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 128, Runtime: models.RuntimeGvisor}
	raw, err := encodeCommand(command{Op: opPlace, SandboxID: "sb-g", OwnerNodeID: c.nodeID, OwnerAPIURL: "http://" + c.nodeID, IncarnationID: "inc-sb-g", Spec: &gvisor})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.raft.raft.Apply(raw, 2*time.Second).Error(); err != nil {
		t.Fatal(err)
	}
	applyDrain(t, c, c.nodeID)

	// The source with the switch off: nothing to move.
	seedCapacityHeartbeats(c, []Member{self})
	res, err := c.EvacuateNode(context.Background(), c.nodeID, EvacuateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Moved) != 0 || res.Remaining != 1 || res.RemainingMovable != 0 || len(source.calls) != 0 {
		t.Fatalf("pass with the switch off = %+v, calls %v", res, source.calls)
	}

	seedCapacityHeartbeats(c, labelled(self))
	res, err = c.EvacuateNode(context.Background(), c.nodeID, EvacuateRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(res.Moved, ",") != "sb-g" || res.Remaining != 0 || res.RemainingMovable != 0 {
		t.Fatalf("pass = %+v", res)
	}
	if owner, err := c.OwnerOf("sb-g"); err != nil || owner.NodeID != "wkr-b" {
		t.Fatalf("sb-g owner = %+v %v", owner, err)
	}
	if got := strings.Join(source.calls, "; "); got != "release sb-g for wkr-b" {
		t.Fatalf("source calls: %s", got)
	}
	if got := strings.Join(target.calls, "; "); got != "import sb-g from "+c.nodeID+"; start sb-g from alpine" {
		t.Fatalf("target calls: %s", got)
	}
}

// A failed import leaves the placement on the source and drops what the
// target has; the source's fence then lapses into a start there.
func TestSnapshotMoveFailedImportStaysOnTheSource(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test: requires real raft socket")
	}
	c, cleanup := newTestClusterWithCfg(t, "ldr-snapf", true, nil, func(cfg *config.Config) { cfg.NodeRole = config.NodeRoleMixed })
	defer cleanup()
	waitForLeader(t, c, 10*time.Second)
	source, target := &fakeSnapshotMoves{}, &fakeSnapshotMoves{importErr: errors.New("disk full")}
	c.AttachMoveHandler(source)
	c.moves.mu.Lock()
	c.moves.peers = map[string]MoveHandler{"wkr-b": target}
	c.moves.mu.Unlock()
	room := capacity.Snapshot{HostCPUCores: 8, HostMemoryTotalMB: 16384, CPUBudget: 8, MemoryBudgetMB: 16384, CanAdmit: true,
		SupportedRuntimes: []string{models.RuntimeFirecracker}}
	self, _ := c.gossip.lookupMember(c.nodeID)
	self.Role = config.NodeRoleMixed
	seedGossipView(t, c, []Member{self, {NodeID: "wkr-b", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://wkr-b", Capacity: room, Arch: self.Arch, Version: self.Version}})
	placeFirecracker(t, c, "sb-vm", c.nodeID, models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 128})
	applyDrain(t, c, c.nodeID)
	res, _ := c.EvacuateNode(context.Background(), c.nodeID, EvacuateRequest{})
	if !strings.Contains(res.Failed["sb-vm"], "disk full") || res.RemainingMovable != 1 {
		t.Fatalf("pass = %+v", res)
	}
	if owner, _ := c.OwnerOf("sb-vm"); owner.NodeID != c.nodeID {
		t.Fatalf("the placement moved on a failed import: %+v", owner)
	}
	if got := strings.Join(target.calls, "; "); got != "import sb-vm from "+c.nodeID+"; drop sb-vm" {
		t.Fatalf("target calls: %s", got)
	}

	// A target on another build cannot restore the snapshot: refused before
	// anything stops.
	source.calls, target.calls = nil, nil
	seedGossipView(t, c, []Member{self, {NodeID: "wkr-b", Alive: true, Role: config.NodeRoleWorker, APIURL: "http://wkr-b", Capacity: room, Arch: self.Arch, Version: "v0.0.0-other"}})
	res, _ = c.EvacuateNode(context.Background(), c.nodeID, EvacuateRequest{})
	if !strings.Contains(res.Failed["sb-vm"], "runs v0.0.0-other") || len(source.calls) != 0 {
		t.Fatalf("pass = %+v, source calls %v", res, source.calls)
	}
}

func TestPlacementWantsSnapshotMove(t *testing.T) {
	fc := func(edit func(*models.CreateSandboxRequest)) Placement {
		spec := &models.CreateSandboxRequest{Runtime: models.RuntimeFirecracker}
		if edit != nil {
			edit(spec)
		}
		return Placement{SandboxID: "sb", Spec: spec}
	}
	gvisor := Placement{SandboxID: "sb", Spec: &models.CreateSandboxRequest{Runtime: models.RuntimeGvisor}}
	mover := Member{NodeID: "a", Capacity: capacity.Snapshot{Labels: map[string]string{CheckpointMovesLabel: "true"}}}
	plain := Member{NodeID: "a"}
	for _, tc := range []struct {
		name   string
		p      Placement
		source Member
		want   bool
	}{
		{"a Firecracker sandbox", fc(nil), plain, true},
		{"with mounts", fc(func(s *models.CreateSandboxRequest) { s.Mounts = []models.MountSpec{{Type: "s3"}} }), plain, false},
		{"with the recreate policy: recreate decides", fc(func(s *models.CreateSandboxRequest) {
			s.Failover = &models.Failover{Policy: models.FailoverPolicyRecreate}
		}), plain, false},
		{"gVisor on a worker that moves them (C21)", gvisor, mover, true},
		{"gVisor on a worker with the switch off", gvisor, plain, false},
		{"runc", Placement{SandboxID: "sb", Spec: &models.CreateSandboxRequest{Runtime: models.RuntimeDocker}}, mover, false},
		{"no spec", Placement{SandboxID: "sb"}, mover, false},
	} {
		if got := placementWantsSnapshotMove(tc.p, tc.source); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
	if why := snapshotTargetFits(fc(nil), Member{Arch: "amd64"}, Member{NodeID: "b", Arch: "arm64"}); !strings.Contains(why, "arm64") {
		t.Fatalf("another architecture: %q", why)
	}
	if why := snapshotTargetFits(fc(nil), Member{Arch: "amd64", Version: "v1"}, Member{Arch: "amd64", Version: "v2"}); !strings.Contains(why, "v2") {
		t.Fatalf("another build: %q", why)
	}
	if why := snapshotTargetFits(fc(nil), Member{Arch: "amd64", Version: "v1"}, Member{Arch: "amd64", Version: "v1"}); why != "" {
		t.Fatalf("the same build refused: %q", why)
	}
	// A gVisor checkpoint goes only to a worker that restores them.
	if why := snapshotTargetFits(gvisor, mover, Member{NodeID: "b"}); !strings.Contains(why, "gVisor") {
		t.Fatalf("a target without the switch: %q", why)
	}
	if why := snapshotTargetFits(gvisor, mover, mover); why != "" {
		t.Fatalf("a target that restores them refused: %q", why)
	}
}

// The snapshot actions reach a handler that has the snapshot half, and are
// refused by one that has not.
func TestRunSnapshotMoveAction(t *testing.T) {
	ctx := context.Background()
	h := &fakeSnapshotMoves{}
	for _, a := range []MoveAction{
		{Action: "release-snapshot", IDs: []string{"sb"}, Target: "b"},
		{Action: "import", IDs: []string{"sb"}, Source: "a"},
		{Action: "drop", IDs: []string{"sb"}},
		{Action: "start-moved", IDs: []string{"sb"}, Recreate: &MoveRecreate{Spec: models.CreateSandboxRequest{Image: "alpine"}}},
	} {
		if _, err := RunMoveAction(ctx, h, a); err != nil {
			t.Fatalf("%s: %v", a.Action, err)
		}
	}
	if got := strings.Join(h.calls, "; "); got != "release sb for b; import sb from a; drop sb; start sb from alpine" {
		t.Fatalf("calls: %s", got)
	}
	for _, a := range []MoveAction{
		{Action: "release-snapshot", IDs: []string{"sb"}},
		{Action: "import", IDs: []string{"sb"}},
		{Action: "drop", IDs: []string{"a", "b"}},
	} {
		if _, err := RunMoveAction(ctx, h, a); err == nil {
			t.Fatalf("%+v was accepted", a)
		}
	}
	if _, err := RunMoveAction(ctx, &fakeMoves{}, MoveAction{Action: "import", IDs: []string{"sb"}, Source: "a"}); err == nil {
		t.Fatal("a handler without the snapshot half took an import")
	}
	h.importErr = errors.New("no room")
	if out, err := RunMoveAction(ctx, h, MoveAction{Action: "import", IDs: []string{"sb"}, Source: "a"}); err != nil || out.Error != "no room" {
		t.Fatalf("a failed import = %+v %v", out, err)
	}
}

// bundlePeer is a worker's view for FetchMoveBundle: the source is srv,
// reached with client.
type bundlePeer struct {
	*Noop
	srv    *httptest.Server
	client *http.Client
}

func (b *bundlePeer) LookupMember(id string) (Member, bool) {
	return Member{NodeID: id, Alive: true, InternalURL: b.srv.URL}, true
}

func (b *bundlePeer) PeerDialMember(Member) (*http.Client, string, error) {
	return b.client, b.srv.URL, nil
}

func (b *bundlePeer) SelfNodeID() string { return "worker-b" }

// A bundle streams for as long as the move allows, past the internal
// client's per-call timeout (F35); the move's own deadline still ends it.
func TestFetchMoveBundleOutlastsTheClientTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != MoveBundlePath("sb-1") || r.Header.Get(PeerNodeIDHeader) != "worker-b" {
			http.Error(w, "wrong request", http.StatusBadRequest)
			return
		}
		for i := 0; i < 4; i++ {
			_, _ = w.Write(bytes.Repeat([]byte{byte('a' + i)}, 1024))
			w.(http.Flusher).Flush()
			time.Sleep(60 * time.Millisecond)
		}
	}))
	defer srv.Close()
	client := srv.Client()
	client.Timeout = 100 * time.Millisecond
	peer := &bundlePeer{Noop: NewNoop("worker-b", "", ""), srv: srv, client: client}
	var got bytes.Buffer
	if err := FetchMoveBundle(context.Background(), peer, "worker-a", "sb-1", &got); err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if got.Len() != 4096 {
		t.Fatalf("got %d bytes, want 4096", got.Len())
	}
	if client.Timeout != 100*time.Millisecond {
		t.Fatal("the shared client was changed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Millisecond)
	defer cancel()
	if err := FetchMoveBundle(ctx, peer, "worker-a", "sb-1", &bytes.Buffer{}); err == nil {
		t.Fatal("the move's deadline did not end the pull")
	}
}

// RecreateInputs is what the owner watcher and a gVisor move's target
// rebuild a sandbox from: its spec, its secrets handle, its ports.
func TestRecreateInputs(t *testing.T) {
	if _, _, _, ok := RecreateInputs(Placement{SandboxID: "sb"}); ok {
		t.Fatal("a placement without a spec gave inputs")
	}
	spec := models.CreateSandboxRequest{Image: "alpine", Runtime: models.RuntimeGvisor}
	p := Placement{SandboxID: "sb", Spec: &spec, IncarnationID: "inc-1", SecretRef: "ref-1", OwnerRef: "acct",
		ExposedPorts: map[int]string{8080: "http"}}
	got, sealed, ports, ok := RecreateInputs(p)
	if !ok || got.Image != "alpine" || sealed.IncarnationID != "inc-1" || sealed.Ref != "ref-1" || sealed.OwnerRef != "acct" ||
		ports[8080].Protocol != "http" {
		t.Fatalf("inputs: %+v %+v %+v %v", got, sealed, ports, ok)
	}
	got.Image = "changed"
	if p.Spec.Image != "alpine" {
		t.Fatal("the inputs share the placement's spec")
	}
}
