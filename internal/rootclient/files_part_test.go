package rootclient

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// TestFilesPartVersionGate (M1 PR 7): the container's files part goes only
// to a helper that lists it. An older helper (PR 6's, which lists no files
// part) is never sent it: a split create or start fails first, with an
// UnsupportedError naming the part, and nothing reaches the helper.
func TestFilesPartVersionGate(t *testing.T) {
	sock := newOwnedSocket(t)
	old := &partsHelper{parts: []string{rootdpb.PartNetns, rootdpb.PartFirewall, rootdpb.PartCgroup}}
	sock.serve(t, old)
	c := New(Config{Socket: sock.path, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = c.Close() })
	ctx := ctxT(t)
	var ue *UnsupportedError
	_, err := c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: "sb-1",
		Setup: &rootdpb.ContainerSetup{TaskFifos: true}})
	if !errors.As(err, &ue) || !strings.Contains(err.Error(), rootdpb.PartFiles) || old.prepares.Load() != 0 {
		t.Fatalf("prepare on an older helper = %v (sent %d)", err, old.prepares.Load())
	}
	err = c.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: "sb-1"})
	if !errors.As(err, &ue) || old.releases.Load() != 0 {
		t.Fatalf("release on an older helper = %v (sent %d)", err, old.releases.Load())
	}

	// A helper that lists it gets both.
	sock2 := newOwnedSocket(t)
	cur := &partsHelper{parts: rootdpb.Parts()}
	sock2.serve(t, cur)
	c2 := New(Config{Socket: sock2.path, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = c2.Close() })
	if _, err := c2.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: "sb-1",
		Setup: &rootdpb.ContainerSetup{TaskFifos: true}}); err != nil || cur.prepares.Load() != 1 {
		t.Fatalf("prepare = %v (sent %d)", err, cur.prepares.Load())
	}
	if err := c2.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{Parts: []string{rootdpb.PartFiles}, ContainerId: "sb-1"}); err != nil || cur.releases.Load() != 1 {
		t.Fatalf("release = %v (sent %d)", err, cur.releases.Load())
	}
}
