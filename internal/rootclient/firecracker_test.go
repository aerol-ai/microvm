package rootclient

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// fcHelper serves the Firecracker calls and records them.
type fcHelper struct {
	*hostsHelper
	features []string
}

func (h *fcHelper) Version(context.Context, *rootdpb.VersionRequest) (*rootdpb.VersionResponse, error) {
	return &rootdpb.VersionResponse{HelperVersion: "n", Api: rootdpb.APIVersion, Features: h.features, Hosts: h.kinds}, nil
}

func (h *fcHelper) PrepareHost(_ context.Context, req *rootdpb.PrepareHostRequest) (*rootdpb.PrepareHostResponse, error) {
	h.note("prepare " + req.GetId() + " " + strings.Join(req.GetFirecracker().GetStage(), ","))
	return &rootdpb.PrepareHostResponse{RunDir: "/srv/jailer/firecracker/" + req.GetId() + "/root",
		StageDir: "/srv/jailer/firecracker/" + req.GetId() + "/stage"}, nil
}

func (h *fcHelper) EnsureTap(_ context.Context, req *rootdpb.EnsureTapRequest) (*rootdpb.EnsureTapResponse, error) {
	h.note("tap " + req.GetName())
	return &rootdpb.EnsureTapResponse{Cidr: "172.16.0.0/30", HostIp: "172.16.0.1", GuestIp: "172.16.0.2", VsockCid: 3}, nil
}

func (h *fcHelper) RemoveTap(_ context.Context, req *rootdpb.RemoveTapRequest) (*rootdpb.RemoveTapResponse, error) {
	h.note("untap " + req.GetName())
	return &rootdpb.RemoveTapResponse{}, nil
}

func (h *fcHelper) MakeFilesystem(_ context.Context, req *rootdpb.MakeFilesystemRequest) (*rootdpb.MakeFilesystemResponse, error) {
	h.note("mkfs " + req.GetId() + " " + req.GetName() + " " + req.GetSource())
	return &rootdpb.MakeFilesystemResponse{}, nil
}

func TestFirecrackerCalls(t *testing.T) {
	h := &fcHelper{hostsHelper: newHostsHelper("firecracker"), features: rootdpb.Features()}
	sock := newOwnedSocket(t)
	sock.serve(t, h)
	c := New(Config{Socket: sock.path, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = c.Close() })
	ctx := ctxT(t)
	root, stage, err := c.PrepareFirecracker(ctx, "sb-1", "rootfs.ext4")
	if err != nil || root != "/srv/jailer/firecracker/sb-1/root" || stage != "/srv/jailer/firecracker/sb-1/stage" {
		t.Fatalf("PrepareFirecracker = %q %q %v", root, stage, err)
	}
	slot, err := c.EnsureTap(ctx, "fctap0")
	if err != nil || slot.GetGuestIp() != "172.16.0.2" {
		t.Fatalf("EnsureTap = %v %v", slot, err)
	}
	if err := c.RemoveTap(ctx, "fctap0"); err != nil {
		t.Fatal(err)
	}
	if err := c.MakeFilesystem(ctx, "sb-1", "rootfs.ext4", "/b", 64); err != nil {
		t.Fatal(err)
	}
	if got := h.seen(); !slices.Equal(got, []string{"prepare sb-1 rootfs.ext4", "tap fctap0", "untap fctap0", "mkfs sb-1 rootfs.ext4 /b"}) {
		t.Fatalf("calls %v", got)
	}
}

// TestFirecrackerCallsTheHelperLacks: a helper whose handshake names no
// Firecracker gets no Firecracker call.
func TestFirecrackerCallsTheHelperLacks(t *testing.T) {
	h := &fcHelper{hostsHelper: newHostsHelper("workerd"), features: []string{rootdpb.FeaturePrepareHost}}
	sock := newOwnedSocket(t)
	sock.serve(t, h)
	c := New(Config{Socket: sock.path, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = c.Close() })
	ctx := ctxT(t)
	if _, _, err := c.PrepareFirecracker(ctx, "sb-1"); err == nil {
		t.Fatal("PrepareFirecracker on a helper with no Firecracker")
	}
	if _, err := c.EnsureTap(ctx, "fctap0"); err == nil {
		t.Fatal("EnsureTap")
	}
	if err := c.RemoveTap(ctx, "fctap0"); err == nil {
		t.Fatal("RemoveTap")
	}
	if err := c.MakeFilesystem(ctx, "sb-1", "overlay.ext4", "", 0); err == nil {
		t.Fatal("MakeFilesystem")
	}
	if len(h.seen()) != 0 {
		t.Fatalf("calls sent: %v", h.seen())
	}
}
