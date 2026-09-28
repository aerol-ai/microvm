package firecracker

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestVersionLess(t *testing.T) {
	cases := []struct {
		name string
		got  [3]int
		want [3]int
		less bool
	}{
		{"major less", [3]int{1, 9, 9}, [3]int{2, 0, 0}, true},
		{"major greater", [3]int{2, 0, 0}, [3]int{1, 8, 0}, false},
		{"minor less", [3]int{1, 7, 9}, [3]int{1, 8, 0}, true},
		{"minor greater", [3]int{1, 9, 0}, [3]int{1, 8, 9}, false},
		{"patch less", [3]int{1, 8, 0}, [3]int{1, 8, 1}, true},
		{"equal", [3]int{1, 8, 0}, [3]int{1, 8, 0}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := versionLess(tc.got[0], tc.got[1], tc.got[2], tc.want[0], tc.want[1], tc.want[2])
			if got != tc.less {
				t.Fatalf("versionLess(%v, %v) = %v, want %v", tc.got, tc.want, got, tc.less)
			}
		})
	}
}

func TestChrootFilePath_JailerZeroIdentitySkipsChown(t *testing.T) {
	d := &Driver{cfg: Config{UseJailer: true, JailerUID: 0, JailerGID: 0}}
	runDir := t.TempDir()
	src := filepath.Join(t.TempDir(), "kernel")
	if err := os.WriteFile(src, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := d.chrootFilePath(runDir, src, kernelFileName)
	if err != nil {
		t.Fatalf("chrootFilePath: %v", err)
	}
	if got != kernelFileName {
		t.Fatalf("path = %q, want %q", got, kernelFileName)
	}
}

func TestStageSnapshotLoadPaths(t *testing.T) {
	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	memPath := filepath.Join(dir, "mem")
	statePath := filepath.Join(dir, "state")
	for _, p := range []string{memPath, statePath} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	d := &Driver{cfg: Config{UseJailer: false}}
	memAPI, stateAPI, err := d.stageSnapshotLoadPaths(runDir, memPath, statePath)
	if err != nil {
		t.Fatalf("stageSnapshotLoadPaths: %v", err)
	}
	if memAPI != memPath || stateAPI != statePath {
		t.Fatalf("paths = %q %q, want originals in direct mode", memAPI, stateAPI)
	}

	d.cfg.UseJailer = true
	d.cfg.JailerUID = os.Getuid()
	d.cfg.JailerGID = os.Getgid()
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	memAPI, stateAPI, err = d.stageSnapshotLoadPaths(runDir, memPath, statePath)
	if err != nil {
		t.Fatalf("jailer stage: %v", err)
	}
	if memAPI != sandboxSnapshotMemoryFileName || stateAPI != sandboxSnapshotStateFileName {
		t.Fatalf("jailer paths = %q %q", memAPI, stateAPI)
	}

	if _, _, err := d.stageSnapshotLoadPaths(runDir, filepath.Join(dir, "missing-mem"), statePath); err == nil || !strings.Contains(err.Error(), "stage snapshot memory") {
		t.Fatalf("memory stage error: got %v", err)
	}
}

func TestProbeToolboxTCP_EarlyReturns(t *testing.T) {
	d := New(Config{PostResumeTimeout: time.Second}, nil)
	d.probeToolboxTCP(context.Background(), "create", "sb", nil, false)
	d.probeToolboxTCP(context.Background(), "create", "sb", &TapSlot{GuestIP: ""}, false)
	d.cfg.PostResumeTimeout = 0
	d.probeToolboxTCP(context.Background(), "create", "sb", &TapSlot{GuestIP: "127.0.0.1"}, false)
}

func TestProbeToolboxTCP_SuccessAndTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", "0"))
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln.Close()

	addr := net.JoinHostPort("127.0.0.1", "2280")
	ln, err = net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("toolbox port in use: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	d := New(Config{PostResumeTimeout: 2 * time.Second}, nil)
	d.probeToolboxTCP(context.Background(), "create", "sb-ok", &TapSlot{
		GuestIP: "127.0.0.1",
		TapName: "tap0",
	}, true)

	d.cfg.PostResumeTimeout = 50 * time.Millisecond
	d.probeToolboxTCP(context.Background(), "create", "sb-miss", &TapSlot{
		GuestIP: "127.0.0.2",
		TapName: "tap1",
	}, false)
}

func TestRuntimeHealth_CachedAndPingFailure(t *testing.T) {
	d := New(Config{}, nil)
	first := d.RuntimeHealth(context.Background())
	if first == "ok" {
		t.Fatalf("empty config should not report ok, got %q", first)
	}
	if !strings.Contains(first, "SB_FIRECRACKER_BINARY") {
		t.Fatalf("unexpected health: %q", first)
	}
	second := d.RuntimeHealth(context.Background())
	if second != first {
		t.Fatalf("cached health changed: %q -> %q", first, second)
	}
}

func TestRequireFirecrackerVersion_Errors(t *testing.T) {
	dir := t.TempDir()
	badExec := filepath.Join(dir, "bad-exec")
	if err := os.WriteFile(badExec, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	d := New(Config{FirecrackerBinary: badExec}, nil)
	if err := d.requireFirecrackerVersion(context.Background(), 1, 8, 0); err == nil || !strings.Contains(err.Error(), "failed to exec") {
		t.Fatalf("exec failure: got %v", err)
	}

	garbage := filepath.Join(dir, "garbage")
	if err := os.WriteFile(garbage, []byte("#!/bin/sh\necho not-a-version\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	d.cfg.FirecrackerBinary = garbage
	if err := d.requireFirecrackerVersion(context.Background(), 1, 8, 0); err == nil || !strings.Contains(err.Error(), "could not parse") {
		t.Fatalf("parse failure: got %v", err)
	}

	old := filepath.Join(dir, "old-fc")
	if err := os.WriteFile(old, []byte("#!/bin/sh\necho Firecracker v1.7.5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	d.cfg.FirecrackerBinary = old
	if err := d.requireFirecrackerVersion(context.Background(), 1, 8, 0); err == nil || !strings.Contains(err.Error(), "requires Firecracker >= 1.8.0") {
		t.Fatalf("version gate: got %v", err)
	}
}

func TestRequireKernelVMGenID_ReadAndMissingFlag(t *testing.T) {
	dir := t.TempDir()
	kernel := filepath.Join(dir, "vmlinux")
	cfg := filepath.Join(dir, "vmlinux.config")
	if err := os.WriteFile(kernel, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("# CONFIG_VMGENID is not set\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := New(Config{KernelImage: kernel}, nil)
	if err := d.requireKernelVMGenID(); err == nil || !strings.Contains(err.Error(), "does not enable CONFIG_VMGENID=y") {
		t.Fatalf("missing flag: got %v", err)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(cfg, 0o000); err != nil {
			t.Fatal(err)
		}
		if err := d.requireKernelVMGenID(); err == nil || !strings.Contains(err.Error(), "could not read kernel config") {
			t.Fatalf("read error: got %v", err)
		}
	}
}

func TestLinkOrCopyRootfs_FallbackOpenAndCreateErrors(t *testing.T) {
	dir := t.TempDir()

	// EPERM/EXDEV fallback with a directory source hits the copy path.
	dst2 := filepath.Join(dir, "dst2")
	if err := linkOrCopyRootfs(dir, dst2); err == nil || !strings.Contains(err.Error(), "copy template rootfs") {
		t.Fatalf("directory fallback: got %v", err)
	}

	// Missing source is a hard link failure, not a fallback path.
	if err := linkOrCopyRootfs(filepath.Join(dir, "missing"), filepath.Join(dir, "dst3")); err == nil || !strings.Contains(err.Error(), "link template rootfs") {
		t.Fatalf("missing source: got %v", err)
	}
}

func TestConfigureVMM_OverlayStaging(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	overlay := filepath.Join(runDir, overlayFileName)
	for _, p := range []string{rootfs, overlay} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := newDriverFixture(t)
	f.driver.cfg.UseJailer = false
	client := newFakeClient()
	req := models.CreateSandboxRequest{CPU: 1, MemoryMB: 128}
	slot := &TapSlot{TapName: "tap0", GuestIP: "10.0.0.2", HostIP: "10.0.0.1", CIDR: "10.0.0.0/30"}
	if err := f.driver.configureVMM(context.Background(), client, req, rootfs, slot, overlay); err != nil {
		t.Fatalf("configureVMM with overlay: %v", err)
	}
	if client.drivePatches[overlayDriveID].PathOnHost == "" && client.drives[overlayDriveID].PathOnHost == "" {
		// PutDrive path — overlay is attached via PutDrive on cold boot.
		if _, ok := client.drives[overlayDriveID]; !ok {
			t.Fatalf("overlay drive missing: %+v", client.drives)
		}
	}
}

func TestConfigureVMMForLoad_OverlayPath(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	mem := filepath.Join(runDir, "mem")
	state := filepath.Join(runDir, "state")
	for _, p := range []string{rootfs, mem, state} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := newDriverFixture(t)
	f.driver.cfg.SnapshotVerifyOnLoad = false
	client := newFakeClient()
	snap := &TemplateResolution{
		HasSnapshot:        true,
		SnapshotMemoryPath: mem,
		SnapshotStatePath:  state,
		SnapshotChecksum:   "",
		HasOverlay:         true,
	}
	overlay := filepath.Join(runDir, overlayFileName)
	if err := os.WriteFile(overlay, []byte("o"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.driver.configureVMMForLoad(context.Background(), client, snap, rootfs, &TapSlot{TapName: "tap0"}, overlay); err != nil {
		t.Fatalf("configureVMMForLoad: %v", err)
	}
}

func TestPing_KernelStatErrorWrapped(t *testing.T) {
	dir := t.TempDir()
	fc := filepath.Join(dir, "fc")
	jailer := filepath.Join(dir, "jailer")
	for _, p := range []string{fc, jailer} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	d := New(Config{FirecrackerBinary: fc, JailerBinary: jailer, KernelImage: filepath.Join(dir, "missing-kernel")}, nil)
	if err := d.Ping(context.Background()); err == nil || !strings.Contains(err.Error(), "SB_FIRECRACKER_KERNEL") {
		t.Fatalf("kernel stat: got %v", err)
	}
}

func TestConfigureVMM_PutNetworkAndVsock(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	if err := os.WriteFile(rootfs, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := newDriverFixture(t)
	client := newFakeClient()
	client.nicErr = os.ErrPermission
	slot := &TapSlot{TapName: "tap0", GuestIP: "10.0.0.2", HostIP: "10.0.0.1", CIDR: "10.0.0.0/30"}
	err := f.driver.configureVMM(context.Background(), client, models.CreateSandboxRequest{CPU: 1, MemoryMB: 128}, rootfs, slot, "")
	if err == nil || !strings.Contains(err.Error(), "PutNetworkInterface") {
		t.Fatalf("network error: got %v", err)
	}
}

func TestDriver_Create_InvalidSandboxID(t *testing.T) {
	f := newDriverFixture(t)
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "bad/id", "tok", nil); err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("invalid id: got %v", err)
	}
}

func TestConfigureVMM_ErrorBranches(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	if err := os.WriteFile(rootfs, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	slot := &TapSlot{TapName: "tap0", GuestIP: "10.0.0.2", HostIP: "10.0.0.1", CIDR: "10.0.0.0/30"}
	req := models.CreateSandboxRequest{CPU: 1, MemoryMB: 128}
	f := newDriverFixture(t)

	cases := []struct {
		name string
		mut  func(*fakeClient)
		want string
	}{
		{"PutMachineConfig", func(c *fakeClient) { c.machineErr = os.ErrPermission }, "PutMachineConfig"},
		{"PutBootSource", func(c *fakeClient) { c.bootErr = os.ErrPermission }, "PutBootSource"},
		{"PutDrive root", func(c *fakeClient) { c.driveErr = os.ErrPermission }, "PutDrive root"},
		{"PutVsock", func(c *fakeClient) { c.vsockErr = os.ErrPermission }, "PutVsock"},
		{"PutNetworkInterface", func(c *fakeClient) { c.nicErr = os.ErrPermission }, "PutNetworkInterface"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client := newFakeClient()
			tc.mut(client)
			err := f.driver.configureVMM(context.Background(), client, req, rootfs, slot, "")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("configureVMM: got %v, want %q", err, tc.want)
			}
		})
	}

	overlay := filepath.Join(runDir, overlayFileName)
	if err := os.WriteFile(overlay, []byte("o"), 0o644); err != nil {
		t.Fatal(err)
	}
	client := &selectiveDriveErrClient{fakeClient: newFakeClient(), failDriveID: overlayDriveID}
	if err := f.driver.configureVMM(context.Background(), client, req, rootfs, slot, overlay); err == nil || !strings.Contains(err.Error(), "PutDrive overlay") {
		t.Fatalf("overlay PutDrive: got %v", err)
	}
}

type selectiveDriveErrClient struct {
	*fakeClient
	failDriveID string
}

func (c *selectiveDriveErrClient) PutDrive(ctx context.Context, id string, drv firecracker.Drive) error {
	if id == c.failDriveID {
		return os.ErrPermission
	}
	return c.fakeClient.PutDrive(ctx, id, drv)
}

func TestChrootFilePath_ChownFailure(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can chown to any identity")
	}
	d := &Driver{cfg: Config{UseJailer: true, JailerUID: 1, JailerGID: 1}}
	runDir := t.TempDir()
	src := filepath.Join(t.TempDir(), "kernel")
	if err := os.WriteFile(src, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := d.chrootFilePath(runDir, src, kernelFileName); err == nil || !strings.Contains(err.Error(), "chown") {
		t.Fatalf("chown failure: got %v", err)
	}
}

func TestRequireKernelVMGenID_Success(t *testing.T) {
	dir := t.TempDir()
	kernel := filepath.Join(dir, "vmlinux")
	cfg := kernel + ".config"
	if err := os.WriteFile(kernel, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfg, []byte("CONFIG_VMGENID=y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := New(Config{KernelImage: kernel}, nil)
	if err := d.requireKernelVMGenID(); err != nil {
		t.Fatalf("requireKernelVMGenID: %v", err)
	}
}

func TestConfigureVMMForLoad_OverlayPatchError(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	mem := filepath.Join(runDir, "mem")
	state := filepath.Join(runDir, "state")
	overlay := filepath.Join(runDir, overlayFileName)
	for _, p := range []string{rootfs, mem, state, overlay} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := newDriverFixture(t)
	client := &selectivePatchErrClient{fakeClient: newFakeClient(), failDriveID: overlayDriveID}
	snap := &TemplateResolution{
		HasSnapshot: true, HasOverlay: true,
		SnapshotMemoryPath: mem, SnapshotStatePath: state,
	}
	if err := f.driver.configureVMMForLoad(context.Background(), client, snap, rootfs, &TapSlot{TapName: "tap0"}, overlay); err == nil || !strings.Contains(err.Error(), "PatchDrive overlay") {
		t.Fatalf("overlay patch: got %v", err)
	}
}

func TestCreate_PreconditionAndTemplateErrors(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.KernelImage = filepath.Join(t.TempDir(), "missing-kernel")
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-kernel", "tok", nil); err == nil || !strings.Contains(err.Error(), "kernel") {
		t.Fatalf("kernel unreachable: got %v", err)
	}

	f.driver.cfg.KernelImage = f.kernel
	f.driver.cfg.OverlayEnabled = false
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, OverlaySizeGB: 1,
	}, "sb-overlay-off", "tok", nil); err == nil || !strings.Contains(err.Error(), "overlay drive disabled") {
		t.Fatalf("overlay disabled: got %v", err)
	}

	f.driver.cfg.OverlayEnabled = true
	f.driver.SetTemplateResolver(&fakeTemplateResolver{resolveErr: os.ErrPermission})
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-bad",
	}, "sb-resolve", "tok", nil); err == nil || !strings.Contains(err.Error(), "template \"tpl-bad\" resolve") {
		t.Fatalf("template resolve: got %v", err)
	}

	f.driver.SetTemplateResolver(nil)
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-no-resolver",
	}, "sb-no-resolver", "tok", nil); err == nil || !strings.Contains(err.Error(), "template resolver not registered") {
		t.Fatalf("missing resolver: got %v", err)
	}
}

func TestCreate_SnapshotLoadOverlayMismatch(t *testing.T) {
	f := newDriverFixture(t)
	rootfs := filepath.Join(t.TempDir(), "rootfs.ext4")
	if err := os.WriteFile(rootfs, []byte("r"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.driver.SetTemplateResolver(&fakeTemplateResolver{
		rootfsPath: rootfs, hasSnapshot: true, hasOverlay: false,
		snapshotMemoryPath: filepath.Join(t.TempDir(), "m"),
		snapshotStatePath:  filepath.Join(t.TempDir(), "s"),
	})
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl", OverlaySizeGB: 1,
	}, "sb-snap-overlay", "tok", nil); err == nil || !strings.Contains(err.Error(), "no overlay drive in its snapshot state") {
		t.Fatalf("snapshot overlay mismatch: got %v", err)
	}
}

func TestCreate_SpawnAndTapAllocateFailures(t *testing.T) {
	f := newDriverFixture(t)
	f.pool.nextErr = os.ErrPermission
	f.pool.relErr = os.ErrPermission
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-tap-fail", "tok", nil); err == nil || !strings.Contains(err.Error(), "tap allocate") {
		t.Fatalf("tap allocate: got %v", err)
	}

	f.pool.nextErr = nil
	f.driver.SetSpawner(func(Config, string) (VMMHandle, error) {
		return nil, os.ErrPermission
	})
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-spawn-fail", "tok", nil); err == nil || !strings.Contains(err.Error(), "spawn handle") {
		t.Fatalf("spawn: got %v", err)
	}
}

func TestCreate_ColdBootWithToolboxInject(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.ToolboxBinaryPath = "/opt/toolboxd"
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-toolbox-inject", "tok", nil); err != nil {
		t.Fatalf("Create with toolbox inject: %v", err)
	}
}

func TestCreate_TapEnsureAndRootfsBuildFailures(t *testing.T) {
	f := newDriverFixture(t)
	f.tapHost.ensureErr = os.ErrPermission
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-tap-ensure", "tok", nil); err == nil || !strings.Contains(err.Error(), "tap host ensure") {
		t.Fatalf("tap ensure: got %v", err)
	}

	f.tapHost.ensureErr = nil
	f.rootfs.nextErr = os.ErrPermission
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-rootfs-fail", "tok", nil); err == nil || !strings.Contains(err.Error(), "rootfs build") {
		t.Fatalf("rootfs build: got %v", err)
	}
}

func TestCreate_SnapshotLoadVerifyCorruptRefusesLoad(t *testing.T) {
	f := newDriverFixture(t)
	rootfs := filepath.Join(t.TempDir(), "rootfs.ext4")
	mem, state, _ := writeVerifyCacheFiles(t, t.TempDir(), "m", "s")
	if err := os.WriteFile(rootfs, []byte("r"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.driver.cfg.SnapshotVerifyOnLoad = true
	f.driver.SetTemplateResolver(&fakeTemplateResolver{
		rootfsPath: rootfs, hasSnapshot: true,
		snapshotMemoryPath: mem, snapshotStatePath: state,
		snapshotChecksum: "sha256:" + strings.Repeat("0", 64) + "|sha256:" + strings.Repeat("0", 64),
		snapshotVsockCID: 200,
	})
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-corrupt",
	}, "sb-corrupt-load", "tok", nil); err == nil || !strings.Contains(err.Error(), "snapshot integrity") {
		t.Fatalf("corrupt load: got %v", err)
	}
	if f.client.snapshotLoad != nil {
		t.Fatalf("LoadSnapshot should not run on corrupt checksum: %+v", f.client.snapshotLoad)
	}
}

func TestCreate_TemplateColdBootStaged(t *testing.T) {
	f := newDriverFixture(t)
	rootfs := filepath.Join(t.TempDir(), "rootfs.ext4")
	if err := os.WriteFile(rootfs, []byte("r"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.driver.SetTemplateResolver(&fakeTemplateResolver{
		rootfsPath: rootfs, hasSnapshot: false,
	})
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-cold",
	}, "sb-tpl-cold", "tok", nil); err != nil {
		t.Fatalf("template cold boot: %v", err)
	}
}

func TestConfigureVMM_JailerKernelStageFailure(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	if err := os.WriteFile(rootfs, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := newDriverFixture(t)
	f.driver.cfg.UseJailer = true
	f.driver.cfg.JailerUID = 1
	f.driver.cfg.JailerGID = 1
	if os.Getuid() == 0 {
		t.Skip("root can chown to any identity")
	}
	err := f.driver.configureVMM(context.Background(), newFakeClient(), models.CreateSandboxRequest{CPU: 1, MemoryMB: 128},
		rootfs, &TapSlot{TapName: "tap0", GuestIP: "10.0.0.2", HostIP: "10.0.0.1", CIDR: "10.0.0.0/30"}, "")
	if err == nil || !strings.Contains(err.Error(), "stage kernel") {
		t.Fatalf("kernel stage: got %v", err)
	}
}

func TestPing_BinaryPreconditions(t *testing.T) {
	ctx := context.Background()
	if err := New(Config{}, nil).Ping(ctx); err == nil || !strings.Contains(err.Error(), "SB_FIRECRACKER_BINARY is not set") {
		t.Fatalf("missing fc binary: got %v", err)
	}

	dir := t.TempDir()
	fc := filepath.Join(dir, "firecracker")
	if err := os.WriteFile(fc, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := New(Config{FirecrackerBinary: fc}, nil).Ping(ctx); err == nil || !strings.Contains(err.Error(), "SB_JAILER_BINARY is not set") {
		t.Fatalf("missing jailer: got %v", err)
	}

	missingFC := filepath.Join(dir, "missing-fc")
	jailer := filepath.Join(dir, "jailer")
	if err := os.WriteFile(jailer, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := New(Config{FirecrackerBinary: missingFC, JailerBinary: jailer}, nil).Ping(ctx); err == nil || !strings.Contains(err.Error(), "SB_FIRECRACKER_BINARY") {
		t.Fatalf("bad fc stat: got %v", err)
	}
	if err := New(Config{FirecrackerBinary: fc, JailerBinary: filepath.Join(dir, "missing-jailer")}, nil).Ping(ctx); err == nil || !strings.Contains(err.Error(), "SB_JAILER_BINARY") {
		t.Fatalf("bad jailer stat: got %v", err)
	}
	if err := New(Config{FirecrackerBinary: fc, JailerBinary: jailer}, nil).Ping(ctx); err != nil {
		t.Fatalf("ping ok: %v", err)
	}
}

func TestCreate_EmptyKernelAndOverlayMkfs(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.KernelImage = ""
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-no-kernel", "tok", nil); err == nil || !strings.Contains(err.Error(), "KernelImage not configured") {
		t.Fatalf("empty kernel: got %v", err)
	}

	f.driver.cfg.KernelImage = f.kernel
	mkfs := filepath.Join(t.TempDir(), "mkfs.ext4")
	if err := os.WriteFile(mkfs, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.driver.cfg.OverlayMkfs = true
	f.driver.cfg.Mkfs4Bin = mkfs
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, OverlaySizeGB: 1,
	}, "sb-mkfs", "tok", nil); err != nil {
		t.Fatalf("overlay mkfs create: %v", err)
	}
}

func TestConfigureVMM_JailerHappyWithOverlay(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	overlay := filepath.Join(runDir, overlayFileName)
	for _, p := range []string{rootfs, overlay} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := newDriverFixture(t)
	f.driver.cfg.UseJailer = true
	f.driver.cfg.JailerUID = os.Getuid()
	f.driver.cfg.JailerGID = os.Getgid()
	client := newFakeClient()
	slot := &TapSlot{TapName: "tap0", GuestIP: "10.0.0.2", HostIP: "10.0.0.1", CIDR: "10.0.0.0/30", VsockCID: 3}
	if err := f.driver.configureVMM(context.Background(), client, models.CreateSandboxRequest{CPU: 1, MemoryMB: 128}, rootfs, slot, overlay); err != nil {
		t.Fatalf("configureVMM jailer overlay: %v", err)
	}
	if drv := client.drives[overlayDriveID]; drv.PathOnHost != overlayFileName {
		t.Fatalf("overlay path = %q, want %q", drv.PathOnHost, overlayFileName)
	}
}

func TestConfigureVMMForLoad_JailerOverlayStaging(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	mem := filepath.Join(runDir, "mem")
	state := filepath.Join(runDir, "state")
	overlay := filepath.Join(runDir, overlayFileName)
	for _, p := range []string{rootfs, mem, state, overlay} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := newDriverFixture(t)
	f.driver.cfg.UseJailer = true
	f.driver.cfg.JailerUID = os.Getuid()
	f.driver.cfg.JailerGID = os.Getgid()
	snap := &TemplateResolution{
		HasSnapshot: true, HasOverlay: true,
		SnapshotMemoryPath: mem, SnapshotStatePath: state,
	}
	if err := f.driver.configureVMMForLoad(context.Background(), newFakeClient(), snap, rootfs, &TapSlot{TapName: "tap0"}, overlay); err != nil {
		t.Fatalf("configureVMMForLoad jailer: %v", err)
	}
}

func TestStageSnapshotLoadPaths_StateStageError(t *testing.T) {
	runDir := t.TempDir()
	mem := filepath.Join(t.TempDir(), "mem")
	if err := os.WriteFile(mem, []byte("m"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Driver{cfg: Config{UseJailer: true, JailerUID: os.Getuid(), JailerGID: os.Getgid()}}
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.stageSnapshotLoadPaths(runDir, mem, filepath.Join(t.TempDir(), "missing-state")); err == nil || !strings.Contains(err.Error(), "stage snapshot state") {
		t.Fatalf("state stage: got %v", err)
	}
}

func TestCreate_TemplateRootfsStageFailure(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.SetTemplateResolver(&fakeTemplateResolver{
		rootfsPath:  filepath.Join(t.TempDir(), "missing-rootfs.ext4"),
		hasSnapshot: true, snapshotMemoryPath: "m", snapshotStatePath: "s",
	})
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-bad-rootfs",
	}, "sb-bad-rootfs", "tok", nil); err == nil || !strings.Contains(err.Error(), "template stage") {
		t.Fatalf("template stage: got %v", err)
	}
}

func TestCreate_WarmHit_PostResumeDialWarn(t *testing.T) {
	f := newDriverFixture(t)
	stageWarmFixture(t, f)
	stageWarmTemplate(t, f, false)
	f.vsock.errOnDialIdx = 2
	state, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-warm",
	}, "sb-warm-post-resume-warn", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if state == nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("state = %+v", state)
	}
}

func TestRequireKernelVMGenID_ConfigInDir(t *testing.T) {
	dir := t.TempDir()
	kernel := filepath.Join(dir, "vmlinux")
	if err := os.WriteFile(kernel, []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config"), []byte("CONFIG_VMGENID=y\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := New(Config{KernelImage: kernel}, nil)
	if err := d.requireKernelVMGenID(); err != nil {
		t.Fatalf("config in dir: %v", err)
	}
}

func TestConfigureVMMForLoad_RootfsPatchError(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	mem := filepath.Join(runDir, "mem")
	state := filepath.Join(runDir, "state")
	for _, p := range []string{rootfs, mem, state} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	f := newDriverFixture(t)
	client := &selectivePatchErrClient{fakeClient: newFakeClient(), failDriveID: rootDriveID}
	snap := &TemplateResolution{HasSnapshot: true, SnapshotMemoryPath: mem, SnapshotStatePath: state}
	if err := f.driver.configureVMMForLoad(context.Background(), client, snap, rootfs, &TapSlot{TapName: "tap0"}, ""); err == nil || !strings.Contains(err.Error(), "PatchDrive rootfs") {
		t.Fatalf("rootfs patch: got %v", err)
	}
}

func TestLinkOrCopyRootfs_EXDEVFallbackPaths(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.ext4")
	if err := os.WriteFile(src, []byte("rootfs"), 0o600); err != nil {
		t.Fatal(err)
	}
	orig := linkRootfsFn
	t.Cleanup(func() { linkRootfsFn = orig })

	linkRootfsFn = func(string, string) error { return syscall.EXDEV }
	dst := filepath.Join(dir, "dst.ext4")
	if err := linkOrCopyRootfs(src, dst); err != nil {
		t.Fatalf("EXDEV copy: %v", err)
	}
	got, _ := os.ReadFile(dst)
	if string(got) != "rootfs" {
		t.Fatalf("copied = %q", got)
	}

	// Open-src failure after EXDEV.
	missing := filepath.Join(dir, "missing.ext4")
	if err := linkOrCopyRootfs(missing, filepath.Join(dir, "dst2")); err == nil || !strings.Contains(err.Error(), "open template rootfs") {
		t.Fatalf("open after EXDEV: %v", err)
	}

	// Create-dst failure: destination parent missing.
	if err := linkOrCopyRootfs(src, filepath.Join(dir, "nope", "dst3")); err == nil || !strings.Contains(err.Error(), "create staged rootfs") {
		t.Fatalf("create after EXDEV: %v", err)
	}

	// ErrPermission also falls through to copy.
	linkRootfsFn = func(string, string) error { return os.ErrPermission }
	if err := linkOrCopyRootfs(src, filepath.Join(dir, "dst-perm")); err != nil {
		t.Fatalf("EPERM copy: %v", err)
	}
}

func TestConfigureVMMForLoad_StageArtifactsError(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	if err := os.WriteFile(rootfs, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := newDriverFixture(t)
	f.driver.cfg.UseJailer = true
	f.driver.cfg.JailerUID = os.Getuid()
	f.driver.cfg.JailerGID = os.Getgid()
	snap := &TemplateResolution{
		HasSnapshot:        true,
		SnapshotMemoryPath: filepath.Join(t.TempDir(), "missing-mem"),
		SnapshotStatePath:  filepath.Join(t.TempDir(), "missing-state"),
	}
	if err := f.driver.configureVMMForLoad(context.Background(), newFakeClient(), snap, rootfs, &TapSlot{TapName: "tap0"}, ""); err == nil || !strings.Contains(err.Error(), "stage snapshot load artifacts") {
		t.Fatalf("stage artifacts: got %v", err)
	}
}
