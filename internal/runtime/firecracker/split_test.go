package firecracker

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeSplit is the root helper's Firecracker calls, on a jail tree in a
// temp folder laid out as the helper lays it out.
type fakeSplit struct {
	base string

	mu       sync.Mutex
	calls    []string
	slot     TapSlot
	spawnErr error
	stopErr  error
	tapErr   error
	mkfsErr  error
	shareErr error
	outErr   error
	procs    map[string]*fakeSplitProc
}

func newFakeSplit(t *testing.T) *fakeSplit {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "fcs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return &fakeSplit{base: dir, procs: map[string]*fakeSplitProc{},
		slot: TapSlot{TapName: "fctap-test", CIDR: "172.16.0.0/30", HostIP: "172.16.0.1", GuestIP: "172.16.0.2", VsockCID: 3}}
}

func (f *fakeSplit) note(c string) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
}

func (f *fakeSplit) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

func (f *fakeSplit) jail(id string) (root, stage string) {
	dir := filepath.Join(f.base, "firecracker", id)
	return filepath.Join(dir, "root"), filepath.Join(dir, "stage")
}

func (f *fakeSplit) PrepareFirecracker(_ context.Context, id string, stage ...string) (string, string, error) {
	f.note(strings.TrimSpace("prepare " + id + " " + strings.Join(stage, ",")))
	root, st := f.jail(id)
	for _, d := range []string{root, st} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return "", "", err
		}
	}
	for _, name := range stage {
		if err := os.Rename(filepath.Join(st, name), filepath.Join(root, name)); err != nil {
			return "", "", err
		}
	}
	return root, st, nil
}

type fakeSplitProc struct {
	pid  int
	done chan struct{}
	once sync.Once
	sigs []syscall.Signal
}

func (p *fakeSplitProc) Signal(s syscall.Signal) error {
	p.sigs = append(p.sigs, s)
	p.once.Do(func() { close(p.done) })
	return nil
}
func (p *fakeSplitProc) Done() <-chan struct{} { return p.done }
func (p *fakeSplitProc) Close() error          { return nil }
func (p *fakeSplitProc) Pid() int              { return p.pid }
func (p *fakeSplitProc) StartTicks() uint64    { return 7 }

func (f *fakeSplit) SpawnFirecracker(_ context.Context, id string) (SplitProcess, error) {
	f.note("spawn " + id)
	if f.spawnErr != nil {
		return nil, f.spawnErr
	}
	root, _ := f.jail(id)
	if err := os.WriteFile(filepath.Join(root, jailerAPISocketName), nil, 0o600); err != nil {
		return nil, err
	}
	p := &fakeSplitProc{pid: 4242, done: make(chan struct{})}
	f.mu.Lock()
	f.procs[id] = p
	f.mu.Unlock()
	return p, nil
}

func (f *fakeSplit) OpenFirecracker(_ context.Context, id string, pid int, _ uint64) (SplitProcess, error) {
	f.note("open " + id)
	return &fakeSplitProc{pid: pid, done: make(chan struct{})}, nil
}

func (f *fakeSplit) StopFirecracker(_ context.Context, id string) error {
	f.note("stop " + id)
	if f.stopErr != nil {
		return f.stopErr
	}
	return os.RemoveAll(filepath.Join(f.base, "firecracker", id))
}

func (f *fakeSplit) EnsureTap(_ context.Context, name string) (TapSlot, error) {
	f.note("tap " + name)
	s := f.slot
	s.TapName = name
	return s, f.tapErr
}

func (f *fakeSplit) RemoveTap(_ context.Context, name string) error {
	f.note("untap " + name)
	return nil
}

func (f *fakeSplit) EnsureSnapshotTap(_ context.Context, name string, cid uint32) (TapSlot, error) {
	f.note("snaptap " + name + " " + strconv.FormatUint(uint64(cid), 10))
	s := f.slot
	s.TapName = name
	return s, f.tapErr
}

// ShareFirecrackerFiles moves each named file from the stage folder into
// the chroot, as the helper links it in and drops the stage name.
func (f *fakeSplit) ShareFirecrackerFiles(_ context.Context, id string, names ...string) error {
	f.note("share " + id + " " + strings.Join(names, ","))
	if f.shareErr != nil {
		return f.shareErr
	}
	root, st := f.jail(id)
	for _, name := range names {
		if err := os.Rename(filepath.Join(st, name), filepath.Join(root, name)); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeSplit) HandOutFirecrackerFiles(_ context.Context, id string, names ...string) error {
	f.note("hand-out " + id + " " + strings.Join(names, ","))
	return f.outErr
}

func (f *fakeSplit) MakeFilesystem(_ context.Context, id, name, source string, size uint64) error {
	f.note(strings.TrimSpace("mkfs " + id + " " + name + " " + source))
	if f.mkfsErr != nil {
		return f.mkfsErr
	}
	_, st := f.jail(id)
	return os.WriteFile(filepath.Join(st, name), []byte("ext4"), 0o600)
}

// splitDriver is a driver in privilege mode split over f, with the create
// fakes for everything else.
func splitDriver(t *testing.T, f *fakeSplit) (*Driver, *fakeClient, *fakeVsockDialer, *fakeRootfs) {
	t.Helper()
	client, vsock, rootfs := newFakeClient(), newFakeVsockDialer(), &fakeRootfs{}
	d := New(Config{KernelImage: "/var/lib/aerolvm-rootd/vmlinux", RunDir: t.TempDir(), TemplatesDir: t.TempDir(), UseJailer: true,
		JailerChrootBase: f.base, OverlayEnabled: true, OverlayMkfs: true, Mkfs4Bin: "/sbin/mkfs.ext4", JailerUID: 1500, JailerGID: 1500}, nil)
	d.SetPool(newFakePool())
	d.SetRootfsBuilder(rootfs)
	d.SetVsockDialer(vsock)
	d.SetClientFactory(func(string) VMMClient { return client })
	d.SetSplit(f)
	return d, client, vsock, rootfs
}

// TestSplitCreate: a cold boot in split mode builds the disks in the
// stage folder, has the helper make the overlay's filesystem and move both
// into the chroot, gives the API only chroot names, starts the VM, has the
// helper share its sockets, and handshakes on the chroot's vsock socket.
func TestSplitCreate(t *testing.T) {
	f := newFakeSplit(t)
	d, client, vsock, rootfs := splitDriver(t, f)
	if _, err := d.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 256,
		OverlaySizeGB: 1}, "sb-split", "tok", nil); err != nil {
		t.Fatal(err)
	}
	root, stage := f.jail("sb-split")
	if rootfs.lastOutput != filepath.Join(stage, rootfsFileName) {
		t.Fatalf("rootfs built at %s, want the stage folder", rootfs.lastOutput)
	}
	want := []string{"prepare sb-split", "tap fctap-test", "spawn sb-split", "mkfs sb-split overlay.ext4",
		"prepare sb-split rootfs.ext4", "prepare sb-split overlay.ext4", "prepare sb-split"}
	if got := f.seen(); !slices.Equal(got, want) {
		t.Fatalf("helper calls\n got %v\nwant %v", got, want)
	}
	if client.bs == nil || client.bs.KernelImagePath != kernelFileName || client.drives[rootDriveID].PathOnHost != rootfsFileName ||
		client.drives[overlayDriveID].PathOnHost != overlayFileName {
		t.Fatalf("API paths: boot %+v drives %+v", client.bs, client.drives)
	}
	if vsock.lastSocketPath != filepath.Join(root, hostVsockUDSName) {
		t.Fatalf("vsock dialed at %s", vsock.lastSocketPath)
	}
	for _, name := range []string{rootfsFileName, overlayFileName} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Errorf("%s not in the chroot: %v", name, err)
		}
	}
	// The ownership lease cannot freeze it: a recreate-policy VM is not let
	// run on a node that writes the lease file (the service asks here).
	if err := d.FenceReady("sb-split"); !errors.Is(err, sbruntime.ErrCannotFreeze) {
		t.Fatalf("FenceReady of a split VM: %v", err)
	}
	if err := d.FenceReady("sb-none"); err != nil {
		t.Fatalf("FenceReady with no VM: %v", err)
	}
	// Destroy ends the VM and its TAP through the helper.
	if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-split"}); err != nil {
		t.Fatal(err)
	}
	got := f.seen()
	if !slices.Contains(got, "stop sb-split") || !slices.Contains(got, "untap fctap-test") {
		t.Fatalf("destroy calls %v", got)
	}
}

func TestSplitCreateFailures(t *testing.T) {
	ctx := context.Background()
	req := models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 128}
	// The helper fails to start the VM: the jail goes, and the TAP.
	f := newFakeSplit(t)
	f.spawnErr = errors.New("jailer: no /dev/kvm")
	d, _, _, _ := splitDriver(t, f)
	if _, err := d.Create(ctx, req, "sb-a", "tok", nil); err == nil || !strings.Contains(err.Error(), "no /dev/kvm") {
		t.Fatalf("spawn failure: %v", err)
	}
	if got := f.seen(); !slices.Contains(got, "stop sb-a") || !slices.Contains(got, "untap fctap-test") {
		t.Fatalf("calls after a failed spawn: %v", got)
	}
	// A TAP the helper lays out otherwise: refused and removed.
	f = newFakeSplit(t)
	f.slot.GuestIP = "172.16.9.9"
	d, _, _, _ = splitDriver(t, f)
	if _, err := d.Create(ctx, req, "sb-b", "tok", nil); err == nil || !strings.Contains(err.Error(), "SB_FIRECRACKER_TAP_BASE_CIDR") {
		t.Fatalf("a TAP layout mismatch: %v", err)
	}
	// An overlay filesystem the helper cannot make.
	f = newFakeSplit(t)
	f.mkfsErr = errors.New("mkfs.ext4: no space")
	d, _, _, _ = splitDriver(t, f)
	if _, err := d.Create(ctx, models.CreateSandboxRequest{Image: "alpine", CPU: 1, MemoryMB: 128, OverlaySizeGB: 1}, "sb-c", "tok", nil); err == nil ||
		!strings.Contains(err.Error(), "no space") {
		t.Fatalf("an overlay mkfs failure: %v", err)
	}
	// A template's snapshot the helper will not share: the load stops,
	// and the jail and the TAP go.
	f = newFakeSplit(t)
	f.shareErr = errors.New("refused: host")
	d, _, _, _ = splitDriver(t, f)
	d.SetTemplateResolver(fakeResolver{res: splitTemplate(t, 7)})
	if _, err := d.Create(ctx, models.CreateSandboxRequest{TemplateID: "tpl-1", CPU: 1, MemoryMB: 128}, "sb-d", "tok", nil); err == nil ||
		!strings.Contains(err.Error(), "refused: host") {
		t.Fatalf("a snapshot load the helper refused: %v", err)
	}
	if got := f.seen(); !slices.Contains(got, "stop sb-d") || !slices.Contains(got, "untap fctap-test") {
		t.Fatalf("calls after a refused load: %v", got)
	}
}

type fakeResolver struct{ res *TemplateResolution }

func (r fakeResolver) Resolve(context.Context, string) (*TemplateResolution, error) {
	return r.res, nil
}

// TestSplitRefusesWarmPool: what split mode does not run yet answers 501
// naming its step (M1 PR 14b), and the lease cannot freeze a VM.
func TestSplitRefusesWarmPool(t *testing.T) {
	d, _, _, _ := splitDriver(t, newFakeSplit(t))
	ctx := context.Background()
	_, err := d.WarmSpawn(ctx, WarmSpawnRequest{})
	if !errors.Is(err, models.ErrRuntimeNotImplemented) || !strings.Contains(err.Error(), "warm VM pool") {
		t.Errorf("WarmSpawn: %v, want a 501 naming the step", err)
	}
	if err := d.Freeze(ctx, "sb-1"); !errors.Is(err, sbruntime.ErrCannotFreeze) {
		t.Fatalf("Freeze: %v", err)
	}
	if err := d.Thaw(ctx, "sb-1"); err != nil {
		t.Fatalf("Thaw: %v", err)
	}
}

func TestSplitVMM(t *testing.T) {
	f := newFakeSplit(t)
	d, _, _, _ := splitDriver(t, f)
	if _, err := d.splitSpawn(d.cfg, "../x"); err == nil {
		t.Fatal("a VM up the tree")
	}
	h, err := d.splitSpawn(d.cfg, "sb-v")
	if err != nil {
		t.Fatal(err)
	}
	v := h.(*splitVMM)
	root, stage := f.jail("sb-v")
	if v.RunDir() != root || v.StageDir() != stage || v.APISocket() != filepath.Join(root, "api.socket") || stageDirOf(v) != stage {
		t.Fatalf("paths %s %s %s", v.RunDir(), v.StageDir(), v.APISocket())
	}
	if v.Pid() != 0 || v.StderrTail() != "" {
		t.Fatal("a VM not started has no pid")
	}
	if err := v.WaitSocket(context.Background(), 20*time.Millisecond); err == nil {
		t.Fatal("WaitSocket with no socket")
	}
	if err := v.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := v.Start(context.Background()); err == nil {
		t.Fatal("Start twice")
	}
	if err := v.WaitSocket(context.Background(), 0); err != nil || v.Pid() != 4242 {
		t.Fatalf("WaitSocket %v, pid %d", err, v.Pid())
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = os.Remove(v.APISocket())
	if err := v.WaitSocket(ctx, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitSocket on an ended call: %v", err)
	}
	if err := v.Shutdown(context.Background(), time.Second); err != nil {
		t.Fatal(err)
	}
	f.procs["sb-v"].Signal(syscall.SIGKILL)
	if v.Pid() != 0 {
		t.Fatal("a VM that is gone keeps its pid")
	}
	f.stopErr = errors.New("helper away")
	if err := v.Kill(); err == nil || v.Cleanup() == nil {
		t.Fatal("a stop the helper refused")
	}
	f.spawnErr = errors.New("busy")
	v2, _ := d.splitSpawn(d.cfg, "sb-w")
	if err := v2.Start(context.Background()); err == nil {
		t.Fatal("a spawn that failed")
	}
	if shareSockets(context.Background(), &fakeVMM{}) != nil {
		t.Fatal("single mode shares nothing")
	}
}

func TestSplitStageAndMkfs(t *testing.T) {
	f := newFakeSplit(t)
	d, _, _, _ := splitDriver(t, f)
	root, stage := f.jail("sb-s")
	if _, _, err := f.PrepareFirecracker(context.Background(), "sb-s"); err != nil {
		t.Fatal(err)
	}
	// The kernel is the helper's own.
	if name, err := d.chrootSharedFile(stage, d.cfg.KernelImage, kernelFileName); err != nil || name != kernelFileName {
		t.Fatalf("kernel: %q %v", name, err)
	}
	// Another kernel, the kernel under another name, a file that is not
	// there: none is shared.
	for _, tc := range []struct{ src, dest string }{{"/other/vmlinux", kernelFileName}, {d.cfg.KernelImage, "other"},
		{"/t/rootfs.ext4", rootfsFileName}} {
		if _, err := d.chrootSharedFile(stage, tc.src, tc.dest); err == nil {
			t.Errorf("shared %s as %s", tc.src, tc.dest)
		}
	}
	if err := os.WriteFile(filepath.Join(stage, rootfsFileName), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if name, err := d.chrootFilePath(stage, filepath.Join(stage, rootfsFileName), rootfsFileName); err != nil || name != rootfsFileName {
		t.Fatalf("rootfs: %q %v", name, err)
	}
	if _, err := os.Stat(filepath.Join(root, rootfsFileName)); err != nil {
		t.Fatalf("rootfs not moved: %v", err)
	}
	for _, tc := range []struct{ src, dest string }{
		{filepath.Join(stage, rootfsFileName), overlayFileName}, // another name
		{"/elsewhere/rootfs.ext4", rootfsFileName},              // not a stage folder
		{filepath.Join(root, rootfsFileName), rootfsFileName},   // the chroot itself
	} {
		if _, err := d.chrootFilePath(stage, tc.src, tc.dest); err == nil {
			t.Errorf("staged %s as %s", tc.src, tc.dest)
		}
	}
	// The OCI builder's mkfs: the root disk, by the helper.
	if err := d.SplitMkfs(context.Background(), "/oci/bundle/rootfs", filepath.Join(stage, rootfsFileName), 300); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.seen(), "mkfs sb-s rootfs.ext4 /oci/bundle/rootfs") {
		t.Fatalf("calls %v", f.seen())
	}
	if err := d.SplitMkfs(context.Background(), "/b", "/templates/t/rootfs.ext4", 300); err == nil {
		t.Fatal("a root disk outside a stage folder")
	}
	if err := d.SplitMkfs(context.Background(), "/b", filepath.Join(stage, rootfsFileName), 0); err == nil {
		t.Fatal("a root disk of no size")
	}
	single := New(Config{}, nil)
	if err := single.SplitMkfs(context.Background(), "/b", filepath.Join(stage, rootfsFileName), 1); err == nil {
		t.Fatal("SplitMkfs in single mode")
	}
	if err := d.makeOverlayFS(context.Background(), "/elsewhere/overlay.ext4"); err == nil {
		t.Fatal("an overlay outside a stage folder")
	}
}

// TestOverlayMkfsSingleMode: single mode still runs mkfs.ext4 -F itself.
func TestOverlayMkfsSingleMode(t *testing.T) {
	dir := t.TempDir()
	argsFile := filepath.Join(dir, "args")
	mkfs := filepath.Join(dir, "mkfs.ext4")
	if err := os.WriteFile(mkfs, []byte("#!/bin/sh\necho \"$@\" > "+argsFile+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	d := New(Config{Mkfs4Bin: mkfs}, nil)
	if err := d.makeOverlayFS(context.Background(), "/run/x/overlay.ext4"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(argsFile); strings.TrimSpace(string(b)) != "-F /run/x/overlay.ext4" {
		t.Fatalf("mkfs args %q", b)
	}
	if err := os.WriteFile(mkfs, []byte("#!/bin/sh\necho bad >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := d.makeOverlayFS(context.Background(), "/run/x/overlay.ext4"); err == nil || !strings.Contains(err.Error(), "bad") {
		t.Fatalf("a mkfs that fails: %v", err)
	}
}

func TestSplitTapHost(t *testing.T) {
	f := newFakeSplit(t)
	h := splitTapHost{h: f}
	ctx := context.Background()
	slot := f.slot
	slot.TapName = "fctap3"
	if err := h.Ensure(ctx, slot); err != nil {
		t.Fatal(err)
	}
	if err := h.Remove(ctx, "fctap3"); err != nil {
		t.Fatal(err)
	}
	// A snapshot's frozen MAC goes to the helper as the CID it holds.
	frozen := slot
	frozen.GuestMAC = "02:00:00:00:00:09"
	if err := h.Ensure(ctx, frozen); err != nil || !slices.Contains(f.seen(), "snaptap fctap3 9") {
		t.Fatalf("a snapshot's frozen MAC: %v %v", err, f.seen())
	}
	frozen.GuestMAC = "aa:bb:cc:00:00:09"
	if err := h.Ensure(ctx, frozen); err == nil {
		t.Fatal("a MAC no guest CID makes")
	}
	f.tapErr = errors.New("refused: tap")
	if err := h.Ensure(ctx, slot); err == nil {
		t.Fatal("a refused TAP")
	}
}

func TestSplitAdoption(t *testing.T) {
	f := newFakeSplit(t)
	d, _, _, _ := splitDriver(t, f)
	p, err := d.splitOpenProcess(context.Background(), "sb-o", 77, 9)
	if err != nil || p == nil || !slices.Contains(f.seen(), "open sb-o") {
		t.Fatalf("open: %v %v", p, f.seen())
	}
	old := vmmGroupOfPID
	t.Cleanup(func() { vmmGroupOfPID = old })
	vmmGroupOfPID = func(int) (string, bool, error) { return "sb-stray", true, nil }
	if err := d.splitKillStray(context.Background(), 88); err != nil || !slices.Contains(f.seen(), "stop sb-stray") {
		t.Fatalf("kill stray: %v %v", err, f.seen())
	}
	vmmGroupOfPID = func(int) (string, bool, error) { return "", false, nil }
	if err := d.splitKillStray(context.Background(), 88); err == nil {
		t.Fatal("a pid in no VM's group")
	}
	vmmGroupOfPID = func(int) (string, bool, error) { return "", false, errors.New("no /proc") }
	if err := d.splitKillStray(context.Background(), 88); err == nil {
		t.Fatal("an unreadable group")
	}
	// placeVMM leaves a split VM where the helper started it.
	moved := false
	oldMove := moveVMMToCgroup
	t.Cleanup(func() { moveVMMToCgroup = oldMove })
	moveVMMToCgroup = func(int, string) error { moved = true; return nil }
	d.placeVMM("sb-o", 77)
	if moved {
		t.Fatal("placeVMM moved a split VM")
	}
}
