package main

import (
	"context"
	"net"
	"path/filepath"
	"testing"

	containersapi "github.com/containerd/containerd/api/services/containers/v1"
	"github.com/containerd/containerd/v2/pkg/namespaces"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// fakeContainers is containerd's containers service, for the list the
// helper's sweep of gone containers' files reads.
type fakeContainers struct {
	containersapi.UnimplementedContainersServer
	byNS map[string][]string
}

func (f *fakeContainers) ListStream(_ *containersapi.ListContainersRequest, s containersapi.Containers_ListStreamServer) error {
	ns, ok := namespaces.Namespace(s.Context())
	if !ok {
		return status.Error(codes.InvalidArgument, "no namespace")
	}
	ids, ok := f.byNS[ns]
	if !ok {
		return status.Error(codes.Unavailable, "containerd is restarting")
	}
	for _, id := range ids {
		if err := s.Send(&containersapi.ListContainerMessage{Container: &containersapi.Container{ID: id}}); err != nil {
			return err
		}
	}
	return nil
}

// TestContainerdContainers (M1 PR 7): the sweep lists the containers of
// the helper's own namespace only, streamed, and a list containerd cannot
// give is an error, never an empty list (which would sweep every
// container's files).
func TestContainerdContainers(t *testing.T) {
	sock := filepath.Join(shortDir(t), "c.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := grpc.NewServer()
	containersapi.RegisterContainersServer(srv, &fakeContainers{byNS: map[string][]string{
		"aerolvm": {"sb-1", "sb-2"}, "other": {"theirs"},
	}})
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(srv.Stop)
	conn, err := grpc.NewClient("unix://"+sock, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	l := containerdContainers{c: containersapi.NewContainersClient(conn), ns: "aerolvm"}
	ids, err := l.ContainerIDs(context.Background())
	if err != nil || len(ids) != 2 || !ids["sb-1"] || !ids["sb-2"] || ids["theirs"] {
		t.Fatalf("ids %v, %v", ids, err)
	}
	down := containerdContainers{c: containersapi.NewContainersClient(conn), ns: "missing"}
	if ids, err := down.ContainerIDs(context.Background()); err == nil || ids != nil {
		t.Fatalf("a failed list = %v, %v", ids, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.ContainerIDs(ctx); err == nil {
		t.Fatal("a cancelled list succeeded")
	}
}
