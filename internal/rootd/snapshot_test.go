package rootd

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"slices"
	"testing"

	snapshotsapi "github.com/containerd/containerd/api/services/snapshots/v1"
	"github.com/containerd/containerd/api/types"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// snapshotsServer is containerd's snapshot service: one active snapshot,
// in one namespace, under one snapshotter.
type snapshotsServer struct {
	snapshotsapi.UnimplementedSnapshotsServer
}

func (snapshotsServer) find(ctx context.Context, snapshotter, key string) error {
	if ns, _ := namespaces.Namespace(ctx); ns != "aerolvm" || snapshotter != "overlayfs" || key != "sb-1" {
		if key == "sb-down" {
			return status.Error(codes.Unavailable, "containerd is restarting")
		}
		return status.Errorf(codes.NotFound, "snapshot %s does not exist", key)
	}
	return nil
}

func (s snapshotsServer) Stat(ctx context.Context, r *snapshotsapi.StatSnapshotRequest) (*snapshotsapi.StatSnapshotResponse, error) {
	if err := s.find(ctx, r.GetSnapshotter(), r.GetKey()); err != nil {
		return nil, err
	}
	return &snapshotsapi.StatSnapshotResponse{Info: &snapshotsapi.Info{Name: r.GetKey(), Parent: "sha256:p", Kind: snapshotsapi.Kind_ACTIVE}}, nil
}

func (s snapshotsServer) Mounts(ctx context.Context, r *snapshotsapi.MountsRequest) (*snapshotsapi.MountsResponse, error) {
	if err := s.find(ctx, r.GetSnapshotter(), r.GetKey()); err != nil {
		return nil, err
	}
	return &snapshotsapi.MountsResponse{Mounts: []*types.Mount{{Type: "overlay", Source: "overlay", Options: []string{"lowerdir=/l"}}}}, nil
}

// TestContainerdSnapshots (M1 PR 7): the helper reads a container's
// snapshot from containerd in its own namespace and under its own
// snapshotter only; one anywhere else is gone to it.
func TestContainerdSnapshots(t *testing.T) {
	sock := filepath.Join(shortDir(t), "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	snapshotsapi.RegisterSnapshotsServer(srv, snapshotsServer{})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx := context.Background()
	s := ContainerdSnapshots(conn, "aerolvm", "overlayfs")
	info, err := s.Stat(ctx, "sb-1")
	if err != nil || info != (SnapshotInfo{Kind: "active", Parent: "sha256:p"}) {
		t.Fatalf("Stat = %+v, %v", info, err)
	}
	ms, err := s.Mounts(ctx, "sb-1")
	if err != nil || len(ms) != 1 || !slices.Equal(ms[0].Options, []string{"lowerdir=/l"}) || ms[0].Type != "overlay" {
		t.Fatalf("Mounts = %+v, %v", ms, err)
	}
	for _, other := range []SnapshotReader{ContainerdSnapshots(conn, "default", "overlayfs"), ContainerdSnapshots(conn, "aerolvm", "native")} {
		if _, err := other.Stat(ctx, "sb-1"); !errors.Is(err, errSnapshotGone) {
			t.Fatalf("another namespace or snapshotter: %v", err)
		}
		if _, err := other.Mounts(ctx, "sb-1"); !errors.Is(err, errSnapshotGone) {
			t.Fatalf("another namespace or snapshotter: %v", err)
		}
	}
	if _, err := s.Stat(ctx, "sb-down"); err == nil || errors.Is(err, errSnapshotGone) {
		t.Fatalf("containerd down = %v", err)
	}
	for kind, want := range map[snapshotsapi.Kind]string{snapshotsapi.Kind_VIEW: "view", snapshotsapi.Kind_COMMITTED: "committed", snapshotsapi.Kind_UNKNOWN: "unknown"} {
		srv2 := grpc.NewServer()
		snapshotsapi.RegisterSnapshotsServer(srv2, kindServer{kind: kind})
		sock2 := filepath.Join(shortDir(t), "k.sock")
		ln2, err := net.Listen("unix", sock2)
		if err != nil {
			t.Fatal(err)
		}
		go func() { _ = srv2.Serve(ln2) }()
		conn2, err := grpc.NewClient("unix://"+sock2, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			t.Fatal(err)
		}
		info, err := ContainerdSnapshots(conn2, "aerolvm", "overlayfs").Stat(ctx, "sb-1")
		_ = conn2.Close()
		srv2.Stop()
		if err != nil || info.Kind != want {
			t.Fatalf("kind %v = %+v, %v", kind, info, err)
		}
	}
}

type kindServer struct {
	snapshotsapi.UnimplementedSnapshotsServer
	kind snapshotsapi.Kind
}

func (k kindServer) Stat(context.Context, *snapshotsapi.StatSnapshotRequest) (*snapshotsapi.StatSnapshotResponse, error) {
	return &snapshotsapi.StatSnapshotResponse{Info: &snapshotsapi.Info{Kind: k.kind}}, nil
}

// TestActiveSnapshotFailures: containerd's own failures are the helper's,
// not refusals.
func TestActiveSnapshotFailures(t *testing.T) {
	snaps := newFakeSnapshots()
	c := &containerCalls{snaps: snaps}
	snaps.set("sb-x", fakeSnap{err: errors.New("containerd is restarting")})
	if _, _, err := c.activeSnapshot(context.Background(), "sb-x"); err == nil || errors.As(err, new(*fileError)) {
		t.Fatalf("a containerd failure = %v", err)
	}
	snaps.set("sb-y", fakeSnap{info: SnapshotInfo{Kind: "active"}})
	mountsErr := &failingMounts{fakeSnapshots: snaps}
	c.snaps = mountsErr
	if _, _, err := c.activeSnapshot(context.Background(), "sb-y"); err == nil || errors.As(err, new(*fileError)) {
		t.Fatalf("a failed mounts read = %v", err)
	}
}

type failingMounts struct{ *fakeSnapshots }

func (failingMounts) Mounts(context.Context, string) ([]rootpolicy.Mount, error) {
	return nil, errors.New("containerd is restarting")
}
