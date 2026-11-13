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
	fcruntime "github.com/aerol-ai/microvm/internal/runtime/firecracker"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
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
}

func (c *moveStubCluster) SelfNodeID() string { return c.self }

func (c *moveStubCluster) PlacementOf(id string) (cluster.Placement, bool) {
	return cluster.Placement{SandboxID: id, OwnerNodeID: c.owner, IncarnationID: "inc-1"}, true
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
	if err := dst.StartMoved(ctx, "sb-vm"); err == nil {
		t.Fatal("started before the swap")
	}
	dstC.owner = "worker-b"
	if err := dst.StartMoved(ctx, "sb-vm"); err != nil {
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
