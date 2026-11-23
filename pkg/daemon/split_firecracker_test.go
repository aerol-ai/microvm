package daemon

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// fakeFirecrackerHelper is the helper's Firecracker calls on top of its host
// calls, recording each.
type fakeFirecrackerHelper struct {
	fakeHostHelper
	tap *rootdpb.EnsureTapResponse
}

func (f *fakeFirecrackerHelper) PrepareFirecracker(_ context.Context, id string, stage ...string) (string, string, error) {
	f.note("prepare-fc " + id + " " + slices.Concat(stage, []string{""})[0])
	return "/srv/jailer/firecracker/" + id + "/root", "/srv/jailer/firecracker/" + id + "/stage", f.err
}

func (f *fakeFirecrackerHelper) EnsureTap(_ context.Context, name string) (*rootdpb.EnsureTapResponse, error) {
	f.note("tap " + name)
	return f.tap, f.err
}

func (f *fakeFirecrackerHelper) RemoveTap(_ context.Context, name string) error {
	f.note("untap " + name)
	return f.err
}

func (f *fakeFirecrackerHelper) MakeFilesystem(_ context.Context, id, name, source string, size uint64) error {
	f.note("mkfs " + id + " " + name + " " + source + " " + fmtU(size))
	return f.err
}

func (f *fakeFirecrackerHelper) EnsureSnapshotTap(_ context.Context, name string, cid uint32) (*rootdpb.EnsureTapResponse, error) {
	f.note("snaptap " + name + " " + fmtU(uint64(cid)))
	return f.tap, f.err
}

func (f *fakeFirecrackerHelper) ShareFirecrackerFiles(_ context.Context, id string, names ...string) error {
	f.note("share " + id + " " + strings.Join(names, ","))
	return f.err
}

func (f *fakeFirecrackerHelper) HandOutFirecrackerFiles(_ context.Context, id string, names ...string) error {
	f.note("hand-out " + id + " " + strings.Join(names, ","))
	return f.err
}

func TestSplitFirecracker(t *testing.T) {
	ctx := context.Background()
	f := &fakeFirecrackerHelper{tap: &rootdpb.EnsureTapResponse{Cidr: "172.16.0.4/30", HostIp: "172.16.0.5", GuestIp: "172.16.0.6", VsockCid: 4}}
	f.resp = &rootdpb.SpawnHostResponse{Pid: 77, StartTicks: 9}
	s := splitFirecracker{h: f}
	root, stage, err := s.PrepareFirecracker(ctx, "sb-1", "rootfs.ext4")
	if err != nil || root != "/srv/jailer/firecracker/sb-1/root" || stage != "/srv/jailer/firecracker/sb-1/stage" {
		t.Fatalf("PrepareFirecracker = %q %q %v", root, stage, err)
	}
	if _, err := s.SpawnFirecracker(ctx, "sb-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenFirecracker(ctx, "sb-1", 77, 9); err != nil {
		t.Fatal(err)
	}
	if err := s.StopFirecracker(ctx, "sb-1"); err != nil {
		t.Fatal(err)
	}
	slot, err := s.EnsureTap(ctx, "fctap1")
	if err != nil || slot.TapName != "fctap1" || slot.GuestIP != "172.16.0.6" || slot.CIDR != "172.16.0.4/30" || slot.VsockCID != 4 {
		t.Fatalf("EnsureTap = %+v %v", slot, err)
	}
	if err := s.RemoveTap(ctx, "fctap1"); err != nil {
		t.Fatal(err)
	}
	if err := s.MakeFilesystem(ctx, "sb-1", "overlay.ext4", "", 0); err != nil {
		t.Fatal(err)
	}
	// A snapshot's TAP and its files (M1 PR 14b).
	if snap, err := s.EnsureSnapshotTap(ctx, "fctap1", 9); err != nil || snap.GuestIP != "172.16.0.6" {
		t.Fatalf("EnsureSnapshotTap = %+v %v", snap, err)
	}
	if err := s.ShareFirecrackerFiles(ctx, "sb-1", "snapshot.memory", "snapshot.state"); err != nil {
		t.Fatal(err)
	}
	if err := s.HandOutFirecrackerFiles(ctx, "sb-1", "rootfs.ext4"); err != nil {
		t.Fatal(err)
	}
	want := []string{"prepare-fc sb-1 rootfs.ext4", "spawn sb-1 0/0/0", "hold sb-1", "open sb-1", "stop sb-1", "tap fctap1",
		"untap fctap1", "mkfs sb-1 overlay.ext4  0", "snaptap fctap1 9", "share sb-1 snapshot.memory,snapshot.state", "hand-out sb-1 rootfs.ext4"}
	if !slices.Equal(f.calls, want) {
		t.Fatalf("calls\n got %v\nwant %v", f.calls, want)
	}
	// A VM the helper answers with no process, and calls that fail.
	f.resp = &rootdpb.SpawnHostResponse{}
	if _, err := s.SpawnFirecracker(ctx, "sb-2"); err == nil {
		t.Fatal("a VM with no process")
	}
	f.err = errors.New("helper away")
	if _, err := s.SpawnFirecracker(ctx, "sb-2"); err == nil {
		t.Fatal("SpawnFirecracker")
	}
	if _, err := s.OpenFirecracker(ctx, "sb-2", 1, 1); err == nil {
		t.Fatal("OpenFirecracker")
	}
	if _, err := s.EnsureTap(ctx, "fctap2"); err == nil {
		t.Fatal("EnsureTap")
	}
	if _, err := s.EnsureSnapshotTap(ctx, "fctap2", 9); err == nil {
		t.Fatal("EnsureSnapshotTap")
	}
}
