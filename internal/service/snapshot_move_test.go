package service

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/runtime"
	fcruntime "github.com/aerol-ai/microvm/internal/runtime/firecracker"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// fakeMoverRuntime is the capacity fake with a snapshot that moves.
type fakeMoverRuntime struct {
	*fakeCapacityRuntime
	snapshot []byte
	imported []byte
	dropped  int
}

func (f *fakeMoverRuntime) ExportSandboxSnapshot(_ context.Context, _ string, w io.Writer) error {
	_, err := w.Write(f.snapshot)
	return err
}

func (f *fakeMoverRuntime) ImportSandboxSnapshot(_ context.Context, _ string, r io.Reader) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	f.imported = raw
	return nil
}

func (f *fakeMoverRuntime) DropImportedSnapshot(context.Context, string) error {
	f.dropped++
	f.imported = nil
	return nil
}

// moveStubCluster is one worker's view: its own ID, every sandbox's owner,
// and a source reached at srv.
type moveStubCluster struct {
	*cluster.Noop
	self, owner string
	srv         *httptest.Server
	// spec is the placement's replicated create request.
	spec *models.CreateSandboxRequest
}

func (c *moveStubCluster) SelfNodeID() string { return c.self }

func (c *moveStubCluster) PlacementOf(id string) (cluster.Placement, bool) {
	return cluster.Placement{SandboxID: id, OwnerNodeID: c.owner, IncarnationID: "inc-1", Spec: c.spec}, true
}

// AuthoritativePlacementsByIDs is the leader's answer: the same placement.
func (c *moveStubCluster) AuthoritativePlacementsByIDs(_ context.Context, ids []string) (map[string]cluster.Placement, error) {
	out := make(map[string]cluster.Placement, len(ids))
	for _, id := range ids {
		out[id], _ = c.PlacementOf(id)
	}
	return out, nil
}

func (c *moveStubCluster) LookupMember(id string) (cluster.Member, bool) {
	return cluster.Member{NodeID: id, Alive: true, InternalURL: c.srv.URL}, true
}

func (c *moveStubCluster) PeerDialMember(cluster.Member) (*http.Client, string, error) {
	return c.srv.Client(), c.srv.URL, nil
}

func moveWorker(t *testing.T, self string, cipher *secrets.Cipher) (*Service, *fakeMoverRuntime, *moveStubCluster) {
	t.Helper()
	svc, _, _ := newCapacityHarness(t, nil, nil)
	rt := &fakeMoverRuntime{fakeCapacityRuntime: &fakeCapacityRuntime{
		startResult: &models.SandboxRuntimeState{ContainerID: "vm", ContainerIP: "172.16.0.6", Status: models.SandboxStatusStarted},
	}}
	svc.firecracker = rt
	svc.admitter = capacity.New(capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384,
		SupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeFirecracker}},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1}, nil)
	svc.cipher = cipher
	svc.store.SetSecretCipher(cipher)
	c := &moveStubCluster{Noop: cluster.NewNoop(self, "", ""), self: self, owner: "worker-a"}
	svc.AttachCluster(c)
	return svc, rt, c
}

// The source serves the bundle as the real route does: to the asking peer.
func serveBundles(src *Service, peer string) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+cluster.PublicInternalMovePath+"{id}/bundle", func(w http.ResponseWriter, r *http.Request) {
		if err := src.ExportMove(r.Context(), r.PathValue("id"), peer, w); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
		}
	})
	return httptest.NewServer(mux)
}

// A Firecracker sandbox moves from worker-a to worker-b with its memory: the
// target ends up with the source's row, toolbox token included, and its
// snapshot, held from the stale sweep until the swap, then starts.
func TestSnapshotMoveBetweenTwoWorkers(t *testing.T) {
	ctx := context.Background()
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "cluster.key"))
	if err != nil {
		t.Fatal(err)
	}
	src, srcRT, _ := moveWorker(t, "worker-a", cipher)
	srcRT.snapshot = bytes.Repeat([]byte("vm memory "), 20_000)
	if err := src.store.Create(ctx, &models.Sandbox{ID: "sb-vm", Name: "sb-vm", Image: "alpine", Runtime: models.RuntimeFirecracker,
		Status: models.SandboxStatusStarted, ContainerID: "vm", ToolboxToken: "guest-token"}); err != nil {
		t.Fatal(err)
	}
	srv := serveBundles(src, "worker-b")
	defer srv.Close()
	dst, dstRT, dstC := moveWorker(t, "worker-b", cipher)
	dstC.srv = srv

	if got := src.ReleaseForSnapshotMove(ctx, "sb-vm", "worker-b"); got != MoveReleased {
		t.Fatalf("release = %q", got)
	}
	if err := dst.ImportMove(ctx, "sb-vm", "worker-a"); err != nil {
		t.Fatalf("import: %v", err)
	}
	if !bytes.Equal(dstRT.imported, srcRT.snapshot) {
		t.Fatalf("the target got %d bytes of snapshot, want %d", len(dstRT.imported), len(srcRT.snapshot))
	}
	row, err := dst.store.Get(ctx, "sb-vm")
	if err != nil || row.Status != models.SandboxStatusStopped || row.StatusReason != statusReasonMovedIn || row.ToolboxToken != "guest-token" {
		t.Fatalf("target row = %+v, %v", row, err)
	}
	if !dst.movesIn.held("sb-vm", time.Now()) {
		t.Fatal("the imported row is not held from the stale-ownership sweep")
	}
	// Not yet the target's: no start.
	if err := dst.StartMoved(ctx, "sb-vm", nil); err == nil {
		t.Fatal("started before the swap")
	}
	dstC.owner = "worker-b"
	if err := dst.StartMoved(ctx, "sb-vm", nil); err != nil {
		t.Fatalf("start after the swap: %v", err)
	}
	if row, _ := dst.store.Get(ctx, "sb-vm"); row.Status != models.SandboxStatusStarted || row.ContainerIP != "172.16.0.6" {
		t.Fatalf("after start: %s at %s", row.Status, row.ContainerIP)
	}
	if dst.movesIn.held("sb-vm", time.Now()) {
		t.Fatal("still held after its start")
	}
	if err := dst.DropMove(ctx, "sb-vm"); err == nil {
		t.Fatal("a sandbox that moved here was dropped")
	}
}

// Only the named target gets the bundle, and only while the sandbox is
// released; an import that cannot open the bundle leaves nothing behind.
func TestSnapshotMoveRefusals(t *testing.T) {
	ctx := context.Background()
	cipher, _ := secrets.NewCipher("", filepath.Join(t.TempDir(), "cluster.key"))
	src, srcRT, _ := moveWorker(t, "worker-a", cipher)
	srcRT.snapshot = []byte("vm memory")
	if err := src.store.Create(ctx, &models.Sandbox{ID: "sb-vm", Name: "sb-vm", Image: "alpine", Runtime: models.RuntimeFirecracker,
		Status: models.SandboxStatusStarted, ContainerID: "vm", ToolboxToken: "guest-token"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := src.ExportMove(ctx, "sb-vm", "worker-b", &out); !errors.Is(err, ErrMoveNotForThisNode) {
		t.Fatalf("export of an unreleased sandbox = %v", err)
	}
	if got := src.ReleaseForSnapshotMove(ctx, "sb-vm", "worker-b"); got != MoveReleased {
		t.Fatalf("release = %q", got)
	}
	if err := src.ExportMove(ctx, "sb-vm", "worker-c", &out); !errors.Is(err, ErrMoveNotForThisNode) {
		t.Fatalf("export to a node the move does not name = %v", err)
	}

	// The target holds another cluster key: nothing opens, nothing stays.
	srv := serveBundles(src, "worker-b")
	defer srv.Close()
	other, _ := secrets.NewCipher("", filepath.Join(t.TempDir(), "other.key"))
	dst, dstRT, dstC := moveWorker(t, "worker-b", other)
	dstC.srv = srv
	if err := dst.ImportMove(ctx, "sb-vm", "worker-a"); err == nil {
		t.Fatal("a bundle sealed with another key was imported")
	}
	if _, err := dst.store.Get(ctx, "sb-vm"); err == nil || dst.movesIn.held("sb-vm", time.Now()) || dstRT.dropped == 0 {
		t.Fatalf("a failed import left something: row err %v, held %v, dropped %d", err, dst.movesIn.held("sb-vm", time.Now()), dstRT.dropped)
	}
	// A sandbox that is not Firecracker is not moved by snapshot.
	_ = src.store.Create(ctx, &models.Sandbox{ID: "sb-ctr", Name: "sb-ctr", Image: "alpine", Runtime: models.RuntimeGvisor, Status: models.SandboxStatusStarted})
	if got := src.ReleaseForSnapshotMove(ctx, "sb-ctr", "worker-b"); !strings.HasPrefix(got, "error:") {
		t.Fatalf("release of a gVisor sandbox = %q", got)
	}
	if got := src.ReleaseForSnapshotMove(ctx, "sb-none", "worker-b"); got != MoveGone {
		t.Fatalf("release of no sandbox = %q", got)
	}
}

// The service is the snapshot half the leader calls, and the Firecracker
// driver the daemon hands it (SetFirecrackerRuntime) is the runtime half.
var (
	_ cluster.SnapshotMoveHandler = (*Service)(nil)
	_ snapshotMover               = (*fcruntime.Driver)(nil)
)

// fakeGvisorMoveRuntime is the containerd driver's half of a gVisor move:
// its stop and create record whether the move asked to save the sandbox or
// to restore it.
type fakeGvisorMoveRuntime struct {
	*fakeMoverRuntime
	stopCheckpointed bool
	createRestored   []bool
	createTokens     []string
	restoreErr       error
}

func (f *fakeGvisorMoveRuntime) Stop(ctx context.Context, _ string) error {
	f.stopCheckpointed = runtime.CheckpointRequested(ctx)
	return nil
}

func (f *fakeGvisorMoveRuntime) Create(ctx context.Context, _ models.CreateSandboxRequest, id, token string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	restore := runtime.RestoreRequested(ctx)
	f.createRestored = append(f.createRestored, restore)
	f.createTokens = append(f.createTokens, token)
	if restore && f.restoreErr != nil {
		return nil, f.restoreErr
	}
	return &models.SandboxRuntimeState{SandboxID: id, ContainerID: id, ContainerIP: "10.88.0.9", Status: models.SandboxStatusStarted}, nil
}

func gvisorWorker(t *testing.T, self string, cipher *secrets.Cipher) (*Service, *fakeGvisorMoveRuntime, *moveStubCluster) {
	t.Helper()
	svc, mover, c := moveWorker(t, self, cipher)
	rt := &fakeGvisorMoveRuntime{fakeMoverRuntime: mover}
	svc.docker = rt
	svc.cfg.GvisorCheckpointMoves = true
	svc.admitter = capacity.New(capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384,
		SupportedRuntimes: []string{models.RuntimeDocker, models.RuntimeGvisor}},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1}, nil)
	c.spec = &models.CreateSandboxRequest{Name: "sb-g", Image: "alpine:3.20", Runtime: models.RuntimeGvisor}
	return svc, rt, c
}

// tokensBefore is a source row's sandbox-token not-before, well in the past.
const tokensBefore = int64(1_700_000_000)

func gvisorMovePair(t *testing.T) (src, dst *Service, srcRT, dstRT *fakeGvisorMoveRuntime, dstC *moveStubCluster) {
	t.Helper()
	ctx := context.Background()
	cipher, err := secrets.NewCipher("", filepath.Join(t.TempDir(), "cluster.key"))
	if err != nil {
		t.Fatal(err)
	}
	src, srcRT, _ = gvisorWorker(t, "worker-a", cipher)
	srcRT.snapshot = bytes.Repeat([]byte("gvisor memory "), 10_000)
	if err := src.store.Create(ctx, &models.Sandbox{ID: "sb-g", Name: "sb-g", Image: "alpine:3.20", Runtime: models.RuntimeGvisor,
		Status: models.SandboxStatusStarted, ContainerID: "sb-g", ToolboxToken: "guest-token",
		SSHPublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsource", TokensNotBefore: tokensBefore}); err != nil {
		t.Fatal(err)
	}
	srv := serveBundles(src, "worker-b")
	t.Cleanup(srv.Close)
	dst, dstRT, dstC = gvisorWorker(t, "worker-b", cipher)
	dstC.srv = srv
	return src, dst, srcRT, dstRT, dstC
}

// A gVisor sandbox moves with its memory (C21): the source's stop saves
// it, the target keeps the bundle's row unstored until the swap, then
// rebuilds the sandbox from the placement with the runtime restoring it,
// keeping the token its toolbox checks, its users' SSH key and the tokens
// issued for it.
func TestCheckpointMoveBetweenTwoWorkers(t *testing.T) {
	ctx := context.Background()
	src, dst, srcRT, dstRT, dstC := gvisorMovePair(t)

	if got := src.ReleaseForSnapshotMove(ctx, "sb-g", "worker-b"); got != MoveReleased {
		t.Fatalf("release = %q", got)
	}
	if !srcRT.stopCheckpointed {
		t.Fatal("the source's stop did not save the sandbox")
	}
	if err := dst.ImportMove(ctx, "sb-g", "worker-a"); err != nil {
		t.Fatalf("import: %v", err)
	}
	if !bytes.Equal(dstRT.imported, srcRT.snapshot) {
		t.Fatalf("the target got %d bytes, want %d", len(dstRT.imported), len(srcRT.snapshot))
	}
	if _, err := dst.store.Get(ctx, "sb-g"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("a row before the swap: %v", err)
	}
	if err := dst.StartMoved(ctx, "sb-g", gvisorRecreate(dstC)); err == nil {
		t.Fatal("started before the swap")
	}
	// A bundle goes out once: a second pull is refused until a release
	// names the target again.
	if err := dst.ImportMove(ctx, "sb-g", "worker-a"); err == nil {
		t.Fatal("a second pull of a bundle the source already gave out")
	}
	src.moveTargets.set("sb-g", "worker-b")
	if err := dst.ImportMove(ctx, "sb-g", "worker-a"); err != nil {
		t.Fatalf("import again: %v", err)
	}
	dstC.owner = "worker-b"
	if err := dst.StartMoved(ctx, "sb-g", gvisorRecreate(dstC)); err != nil {
		t.Fatalf("start after the swap: %v", err)
	}
	row, err := dst.store.Get(ctx, "sb-g")
	if err != nil {
		t.Fatal(err)
	}
	if row.Status != models.SandboxStatusStarted || row.ToolboxToken != "guest-token" || row.SSHPublicKey != "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIsource" ||
		row.TokensNotBefore != tokensBefore || row.StatusReason != statusReasonMovedIn {
		t.Fatalf("target row: status %s, token %q, key %q, not-before %d, reason %q",
			row.Status, row.ToolboxToken, row.SSHPublicKey, row.TokensNotBefore, row.StatusReason)
	}
	if len(dstRT.createRestored) != 1 || !dstRT.createRestored[0] || dstRT.createTokens[0] != "guest-token" {
		t.Fatalf("creates: restore %v, tokens %q", dstRT.createRestored, dstRT.createTokens)
	}
}

// A checkpoint that does not restore (another CPU, a corrupt file) still
// ends with the sandbox running on the target, from its image, under the
// same identity: what it would have done without C21.
func TestCheckpointMoveFallsBackToItsImage(t *testing.T) {
	ctx := context.Background()
	src, dst, _, dstRT, dstC := gvisorMovePair(t)
	dstRT.restoreErr = errors.New("runsc restore: incompatible CPU features")
	if got := src.ReleaseForSnapshotMove(ctx, "sb-g", "worker-b"); got != MoveReleased {
		t.Fatalf("release = %q", got)
	}
	if err := dst.ImportMove(ctx, "sb-g", "worker-a"); err != nil {
		t.Fatal(err)
	}
	dstC.owner = "worker-b"
	if err := dst.StartMoved(ctx, "sb-g", gvisorRecreate(dstC)); err != nil {
		t.Fatalf("start: %v", err)
	}
	if !slicesEqual(dstRT.createRestored, []bool{true, false}) || dstRT.dropped == 0 {
		t.Fatalf("creates %v, dropped %d", dstRT.createRestored, dstRT.dropped)
	}
	if row, err := dst.store.Get(ctx, "sb-g"); err != nil || row.ToolboxToken != "guest-token" {
		t.Fatalf("row %+v, %v", row, err)
	}
}

func slicesEqual(a, b []bool) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestCheckpointMoveRefusals(t *testing.T) {
	ctx := context.Background()
	src, dst, srcRT, dstRT, dstC := gvisorMovePair(t)

	// The kill switch: off, a gVisor sandbox does not move with its memory.
	src.cfg.GvisorCheckpointMoves = false
	if got := src.ReleaseForSnapshotMove(ctx, "sb-g", "worker-b"); !strings.HasPrefix(got, "error:") {
		t.Fatalf("release with the switch off = %q", got)
	}
	src.cfg.GvisorCheckpointMoves = true
	// A stopped one has no memory to save.
	_ = src.store.Create(ctx, &models.Sandbox{ID: "sb-off", Name: "sb-off", Image: "alpine:3.20", Runtime: models.RuntimeGvisor, Status: models.SandboxStatusStopped})
	if got := src.ReleaseForSnapshotMove(ctx, "sb-off", "worker-b"); !strings.Contains(got, "no memory") {
		t.Fatalf("release of a stopped sandbox = %q", got)
	}
	if srcRT.stopCheckpointed {
		t.Fatal("a refused release stopped the sandbox")
	}

	// A move that does not happen leaves nothing on the target.
	if got := src.ReleaseForSnapshotMove(ctx, "sb-g", "worker-b"); got != MoveReleased {
		t.Fatalf("release = %q", got)
	}
	if err := dst.ImportMove(ctx, "sb-g", "worker-a"); err != nil {
		t.Fatal(err)
	}
	if err := dst.DropMove(ctx, "sb-g"); err != nil || dstRT.dropped == 0 || dstRT.imported != nil {
		t.Fatalf("drop: %v, dropped %d", err, dstRT.dropped)
	}
	if err := dst.DropMove(ctx, "sb-g"); err != nil {
		t.Fatalf("a second drop: %v", err)
	}
	// No spec from the leader to rebuild from: the start fails and drops
	// the checkpoint.
	src.moveTargets.set("sb-g", "worker-b")
	if err := dst.ImportMove(ctx, "sb-g", "worker-a"); err != nil {
		t.Fatal(err)
	}
	dstC.owner = "worker-b"
	before := dstRT.dropped
	if err := dst.StartMoved(ctx, "sb-g", nil); err == nil || dstRT.dropped == before {
		t.Fatalf("start without a spec: %v, dropped %d", err, dstRT.dropped)
	}
}

// gvisorRecreate is what the leader sends with start-moved: its read of the
// placement's spec, secrets handle and ports.
func gvisorRecreate(c *moveStubCluster) *cluster.MoveRecreate {
	p, _ := c.PlacementOf("sb-g")
	spec, sealed, ports, _ := cluster.RecreateInputs(p)
	return &cluster.MoveRecreate{Spec: spec, Secrets: sealed, Ports: ports}
}
