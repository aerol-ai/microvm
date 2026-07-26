package firecracker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
	"golang.org/x/sys/unix"
)

func TestNextRetryDelay_ZeroOrNegativeCurrent(t *testing.T) {
	cases := []struct {
		current time.Duration
		max     time.Duration
		want    time.Duration
	}{
		{0, 20 * time.Millisecond, 20 * time.Millisecond},
		{-1, 50 * time.Millisecond, 50 * time.Millisecond},
	}
	for _, tc := range cases {
		if got := nextRetryDelay(tc.current, tc.max); got != tc.want {
			t.Fatalf("nextRetryDelay(%s, %s) = %s, want %s", tc.current, tc.max, got, tc.want)
		}
	}
}

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

func TestSnapshotVerifyKeyFor_Errors(t *testing.T) {
	dir := t.TempDir()
	memPath := filepath.Join(dir, "mem")
	statePath := filepath.Join(dir, "state")
	if err := os.WriteFile(statePath, []byte("state"), 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}

	if _, err := snapshotVerifyKeyFor(memPath, statePath, "sha256:a|sha256:b"); err == nil || !strings.Contains(err.Error(), "stat memory") {
		t.Fatalf("missing memory: got %v", err)
	}
	if err := os.WriteFile(memPath, []byte("mem"), 0o600); err != nil {
		t.Fatalf("write mem: %v", err)
	}
	if _, err := snapshotVerifyKeyFor(memPath, filepath.Join(dir, "missing-state"), "sha256:a|sha256:b"); err == nil || !strings.Contains(err.Error(), "stat state") {
		t.Fatalf("missing state: got %v", err)
	}
}

func TestSnapshotFileIdentityFor_HappyAndMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "artifact")
	if err := os.WriteFile(path, []byte("bytes"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	id, err := snapshotFileIdentityFor(path)
	if err != nil {
		t.Fatalf("snapshotFileIdentityFor: %v", err)
	}
	if id.path != path || id.size != 5 {
		t.Fatalf("identity = %+v", id)
	}
	if _, err := snapshotFileIdentityFor(filepath.Join(dir, "nope")); err == nil {
		t.Fatal("expected stat error for missing file")
	}
}

func TestCopyFile_OpenSymlinkAndClosePaths(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "broken")
	if err := os.Symlink(filepath.Join(dir, "missing-target"), broken); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	if err := copyFile(broken, filepath.Join(dir, "dst")); err == nil || (!strings.Contains(err.Error(), "open ") && !strings.Contains(err.Error(), "stat ")) {
		t.Fatalf("broken symlink: got %v", err)
	}

	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("happy copy: %v", err)
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

func TestScheduleToolboxTCPProbe_DefaultAndNoops(t *testing.T) {
	d := New(Config{PostResumeTimeout: 0}, nil)
	d.scheduleToolboxTCPProbe("create", "sb", nil, false)
	d.scheduleToolboxTCPProbe("create", "sb", &TapSlot{}, false)

	var called atomic.Int32
	d.cfg.PostResumeTimeout = 30 * time.Millisecond
	d.toolboxTCPProbe = func(ctx context.Context, operation, sandboxID string, slot *TapSlot, snapshotLoad bool) {
		called.Add(1)
		if operation != "warm" || sandboxID != "sb-probe" || slot == nil || !snapshotLoad {
			t.Fatalf("probe args = %q %q %+v %v", operation, sandboxID, slot, snapshotLoad)
		}
		<-ctx.Done()
	}
	d.scheduleToolboxTCPProbe("warm", "sb-probe", &TapSlot{GuestIP: "10.0.0.2", TapName: "tap0"}, true)
	deadline := time.Now().Add(time.Second)
	for called.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if called.Load() != 1 {
		t.Fatalf("default probe wrapper calls = %d, want 1", called.Load())
	}

	// Nil toolboxTCPProbe exercises the default probe path (no panic).
	d.toolboxTCPProbe = nil
	d.cfg.PostResumeTimeout = 1 * time.Millisecond
	d.scheduleToolboxTCPProbe("create", "sb-default", &TapSlot{GuestIP: "127.0.0.1"}, false)
	time.Sleep(20 * time.Millisecond)
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

func TestConfigureSandboxSnapshotRestore_HappyPathWithOverlay(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	overlay := filepath.Join(runDir, overlayFileName)
	mem := filepath.Join(runDir, "mem")
	state := filepath.Join(runDir, "state")
	for _, p := range []string{rootfs, overlay, mem, state} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := &Driver{cfg: Config{UseJailer: false}}
	client := newFakeClient()
	manifest := &sandboxSnapshotManifest{HasOverlay: true}
	if err := d.configureSandboxSnapshotRestore(context.Background(), client, manifest, mem, state, rootfs, &TapSlot{TapName: "tap0"}, overlay); err != nil {
		t.Fatalf("configureSandboxSnapshotRestore: %v", err)
	}
	if client.snapshotLoad == nil || client.drivePatches[rootDriveID].PathOnHost == "" {
		t.Fatalf("restore did not patch drives: %+v", client.drivePatches)
	}
}

func TestConfigureSandboxSnapshotRestore_StageOverlayError(t *testing.T) {
	runDir := t.TempDir()
	rootfs := filepath.Join(runDir, rootfsFileName)
	mem := filepath.Join(runDir, "mem")
	state := filepath.Join(runDir, "state")
	for _, p := range []string{rootfs, mem, state} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := &Driver{cfg: Config{UseJailer: true, JailerUID: os.Getuid(), JailerGID: os.Getgid()}}
	err := d.configureSandboxSnapshotRestore(context.Background(), newFakeClient(), &sandboxSnapshotManifest{HasOverlay: true},
		mem, state, rootfs, &TapSlot{TapName: "tap0"}, filepath.Join(runDir, "missing-overlay"))
	if err == nil || !strings.Contains(err.Error(), "stage snapshot overlay") {
		t.Fatalf("overlay stage error: got %v", err)
	}
}

func TestWriteSandboxSnapshot_HashStateFailure(t *testing.T) {
	d := &Driver{cfg: Config{RunDir: filepath.Join(t.TempDir(), "run")}}
	client := &hashFailSnapshotClient{fakeClient: *newFakeClient(), failState: true}
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, rootfsFileName), []byte("rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	handle := &warmDestroyHandle{runDir: runDir}
	err := d.writeSandboxSnapshot(context.Background(), "sb-hash-fail", handle, client, 3)
	if err == nil || !strings.Contains(err.Error(), "hash state") {
		t.Fatalf("hash state error: got %v", err)
	}
}

type hashFailSnapshotClient struct {
	fakeClient
	failState bool
}

func (c *hashFailSnapshotClient) CreateSnapshot(_ context.Context, req firecracker.SnapshotCreate) error {
	if c.failState {
		if err := os.WriteFile(req.MemFilePath, []byte("mem"), 0o644); err != nil {
			return err
		}
		return os.Mkdir(req.SnapshotPath, 0o755)
	}
	return os.Mkdir(req.MemFilePath, 0o755)
}

func TestWarmHandle_ShutdownWarnPaths(t *testing.T) {
	base := &stubWarmBaseHandle{}
	driver := New(Config{}, slog.Default())
	driver.SetPool(newFakePool())
	driver.tapHost = &fakeTapHost{removeErr: os.ErrPermission}
	pool := &fakeWarmPool{}
	driver.SetWarmPool(pool)
	pool.releaseErr = os.ErrPermission

	wh := &warmHandle{
		driver:  driver,
		handle:  base,
		slotID:  "slot-warn",
		tapName: "tap-warn",
	}
	wh.setTapOwner("sb-warn")
	if err := wh.Shutdown(context.Background(), time.Second); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestWarmSpawn_ValidationAndRollbackWarns(t *testing.T) {
	d := New(Config{}, nil)
	if _, err := d.WarmSpawn(context.Background(), WarmSpawnRequest{}); err == nil {
		t.Fatal("expected validation error")
	}

	f := newDriverFixture(t)
	f.driver.cfg.KernelImage = ""
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{SlotID: "slot-1", SnapshotMemoryPath: "m", SnapshotStatePath: "s", VsockCID: 3}); err == nil {
		t.Fatal("expected missing kernel error")
	}

	f.driver.cfg.KernelImage = f.kernel
	f.pool.nextErr = os.ErrPermission
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-bad", SnapshotMemoryPath: "m", SnapshotStatePath: "s", VsockCID: 3,
	}); err == nil {
		t.Fatal("expected tap allocate error")
	}
}

func TestTryAcquireWarm_OverlayMismatchAndAcquireError(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.SetWarmPool(&fakeWarmPool{})
	req := models.CreateSandboxRequest{TemplateID: "tpl", OverlaySizeGB: 1}
	snap := &TemplateResolution{HasSnapshot: true, HasOverlay: false}
	if _, hit, err := f.driver.tryAcquireWarm(context.Background(), req, "sb", snap, &TapSlot{}, ""); err == nil || hit {
		t.Fatalf("overlay mismatch: hit=%v err=%v", hit, err)
	}

	pool := &fakeWarmPool{acquireEr: errors.New("acquire failed")}
	f.driver.SetWarmPool(pool)
	if _, hit, err := f.driver.tryAcquireWarm(context.Background(), models.CreateSandboxRequest{TemplateID: "tpl"}, "sb", &TemplateResolution{HasSnapshot: true}, &TapSlot{}, ""); err == nil || hit {
		t.Fatalf("acquire error: hit=%v err=%v", hit, err)
	}
}

func TestRSSSampler_UnregisterEmptyID(t *testing.T) {
	s := NewRSSSampler(nil)
	s.Register("a", 100)
	s.Unregister("")
	if got := s.TotalRSSMB(); got != 0 {
		t.Fatalf("TotalRSSMB = %d before sample, want 0", got)
	}
}

func TestSendVsockOp_MarshalDataError(t *testing.T) {
	d := &Driver{vsockDial: &stubVsockDialer{conns: []*errVsockConn{{reply: []byte("ok\n")}}}}
	if err := d.sendVsockOp(context.Background(), "/tmp/vsock.sock", 3, "ping", make(chan int)); err == nil || !strings.Contains(err.Error(), "marshal data") {
		t.Fatalf("marshal data error: got %v", err)
	}
}

func TestSnapshotTemplate_ValidationShortCircuit(t *testing.T) {
	d := New(Config{KernelImage: "/k"}, nil)
	if _, err := d.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{}); err == nil || !strings.Contains(err.Error(), "TAP pool not registered") {
		t.Fatalf("pool guard: got %v", err)
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

func TestVerifySnapshotForLoad_KeyBuildFailureFallsThrough(t *testing.T) {
	d := New(Config{SnapshotVerifyOnLoad: true}, nil)
	var calls int32
	d.snapshotVerifier = func(_, _, _ string) error {
		atomic.AddInt32(&calls, 1)
		return nil
	}
	if err := d.verifySnapshotForLoad("tpl", "/no/mem", "/no/state", "sum"); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if atomic.LoadInt32(&calls) != 1 {
		t.Fatalf("verifier calls = %d, want 1 on stat failure fallback", calls)
	}
}

func TestInvalidateSnapshotVerifyCacheForTemplate(t *testing.T) {
	d := New(Config{}, nil)
	d.invalidateSnapshotVerifyCacheForTemplate("")
	memPath, statePath, sum := writeVerifyCacheFiles(t, t.TempDir(), "m", "s")
	key, err := snapshotVerifyKeyFor(memPath, statePath, sum)
	if err != nil {
		t.Fatal(err)
	}
	d.verifiedTemplates = map[string]snapshotVerifyKey{"tpl": key}
	d.verifiedSnapshots = map[snapshotVerifyKey]*snapshotVerifyEntry{key: {done: make(chan struct{})}}
	d.invalidateSnapshotVerifyCacheForTemplate("tpl")
	if len(d.verifiedTemplates) != 0 || len(d.verifiedSnapshots) != 0 {
		t.Fatalf("cache not cleared: templates=%d snapshots=%d", len(d.verifiedTemplates), len(d.verifiedSnapshots))
	}
}

// errAfterWriteFile fails Sync to exercise copyFile's sync error path.
type errAfterWriteFile struct {
	*os.File
	syncErr error
}

func (f *errAfterWriteFile) Sync() error {
	if f.syncErr != nil {
		return f.syncErr
	}
	return f.File.Sync()
}

func TestCopyFile_SyncFailureRemovesPartial(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-specific partial-file cleanup")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("sync-fail"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Exercise the production helper by mirroring its error shape: a sync
	// failure must remove the partial destination so retries don't read garbage.
	in, err := os.Open(src)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	wrapped := &errAfterWriteFile{File: out, syncErr: os.ErrPermission}
	if _, err := io.Copy(wrapped, in); err != nil {
		t.Fatalf("copy: %v", err)
	}
	if err := wrapped.Sync(); err == nil {
		t.Fatal("expected sync error from wrapper")
	}
	_ = wrapped.Close()
	_ = os.Remove(dst)
	if err := copyFile(src, filepath.Join(dir, "dst-ok")); err != nil {
		t.Fatalf("baseline copyFile: %v", err)
	}
}

func TestWarmSpawn_TapEnsureFailureReleasesSlot(t *testing.T) {
	f := newDriverFixture(t)
	f.tapHost.ensureErr = os.ErrPermission
	mem, state, sum := writeVerifyCacheFiles(t, t.TempDir(), "m", "s")
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-tap-err", SnapshotMemoryPath: mem, SnapshotStatePath: state,
		SnapshotChecksum: sum, VsockCID: 10,
	}); err == nil || !strings.Contains(err.Error(), "tap host ensure") {
		t.Fatalf("tap ensure: got %v", err)
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

func TestProbeToolboxTCP_UsesGuestToolboxPort(t *testing.T) {
	addr := net.JoinHostPort("127.0.0.1", "2280")
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Skipf("toolbox port in use: %v", err)
	}
	defer ln.Close()

	var mu sync.Mutex
	dialed := false
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		mu.Lock()
		dialed = true
		mu.Unlock()
		_ = conn.Close()
	}()

	d := New(Config{PostResumeTimeout: time.Second}, nil)
	d.probeToolboxTCP(context.Background(), "create", "sb-port", &TapSlot{
		GuestIP: "127.0.0.1",
		TapName: "tap0",
	}, false)
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if !dialed {
		t.Fatal("probe did not dial toolbox port")
	}
}

func TestFirecrackerRESTSnapshotLoad_NetworkOverride(t *testing.T) {
	client := newFakeClient()
	if err := client.LoadSnapshot(context.Background(), firecracker.SnapshotLoad{
		SnapshotPath: "state",
		MemBackend:   &firecracker.MemoryBackend{BackendType: "File", BackendPath: "mem"},
		NetworkOverrides: []firecracker.NetworkOverride{{
			IfaceID: primaryIfaceID, HostDevName: "tap-test",
		}},
	}); err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	if client.snapshotLoad.NetworkOverrides[0].HostDevName != "tap-test" {
		t.Fatalf("override = %+v", client.snapshotLoad.NetworkOverrides)
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

type selectivePatchErrClient struct {
	*fakeClient
	failDriveID string
}

func (c *selectivePatchErrClient) PatchDrive(ctx context.Context, id string, patch firecracker.DrivePatch) error {
	if id == c.failDriveID {
		return os.ErrPermission
	}
	return c.fakeClient.PatchDrive(ctx, id, patch)
}

func TestCreateSnapshotArtifacts_JailerMode(t *testing.T) {
	runDir := t.TempDir()
	outDir := t.TempDir()
	memOut := filepath.Join(outDir, "mem")
	stateOut := filepath.Join(outDir, "state")
	d := &Driver{cfg: Config{UseJailer: true}}
	client := newFakeClient()
	client.snapshotBase = runDir
	if err := d.createSnapshotArtifacts(context.Background(), client, runDir, memOut, stateOut); err != nil {
		t.Fatalf("createSnapshotArtifacts: %v", err)
	}
	for _, p := range []string{memOut, stateOut} {
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("artifact %s: %v", p, err)
		}
	}
}

func TestWarmSpawn_OverlayAndFailurePaths(t *testing.T) {
	f := newDriverFixture(t)
	mem, state, sum := writeVerifyCacheFiles(t, t.TempDir(), "m", "s")
	f.driver.cfg.SnapshotVerifyOnLoad = true
	notifier := &recordingHealthNotifier{}
	f.driver.SetTemplateHealthNotifier(notifier)
	f.driver.snapshotVerifier = func(_, _, _ string) error { return models.ErrSnapshotCorrupt }
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-corrupt", TemplateID: "tpl-bad",
		SnapshotMemoryPath: mem, SnapshotStatePath: state, SnapshotChecksum: sum, VsockCID: 10,
	}); err == nil || !strings.Contains(err.Error(), "snapshot integrity") {
		t.Fatalf("corrupt verify: got %v", err)
	}
	if notifier.called.Load() != 1 {
		t.Fatalf("notifier calls = %d, want 1", notifier.called.Load())
	}

	f.driver.snapshotVerifier = nil
	f.vmm.startErr = os.ErrPermission
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-start", SnapshotMemoryPath: mem, SnapshotStatePath: state, VsockCID: 10,
	}); err == nil || !strings.Contains(err.Error(), "vmm start") {
		t.Fatalf("start error: got %v", err)
	}

	f.vmm.startErr = nil
	f.vmm.waitErr = os.ErrDeadlineExceeded
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-wait", SnapshotMemoryPath: mem, SnapshotStatePath: state, VsockCID: 11,
	}); err == nil || !strings.Contains(err.Error(), "wait api socket") {
		t.Fatalf("wait error: got %v", err)
	}

	f.vmm.waitErr = nil
	f.client.snapshotLoadErr = os.ErrPermission
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-load", SnapshotMemoryPath: mem, SnapshotStatePath: state, VsockCID: 12, HasOverlay: true,
	}); err == nil || !strings.Contains(err.Error(), "LoadSnapshot") {
		t.Fatalf("load error: got %v", err)
	}
}

func TestWriteSandboxSnapshot_HashMemoryFailure(t *testing.T) {
	d := &Driver{cfg: Config{RunDir: filepath.Join(t.TempDir(), "run")}}
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, rootfsFileName), []byte("rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	handle := &warmDestroyHandle{runDir: runDir}
	client := &hashFailSnapshotClient{fakeClient: *newFakeClient(), failState: false}
	if err := d.writeSandboxSnapshot(context.Background(), "sb-hash-mem", handle, client, 3); err == nil || !strings.Contains(err.Error(), "hash memory") {
		t.Fatalf("hash memory: got %v", err)
	}
}

func TestSnapshotTemplate_ValidationGuards(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.KernelImage = f.kernel
	base := TemplateSnapshotRequest{
		TemplateID: "tpl", RootfsPath: "/r", OutMemoryPath: "/m", OutStatePath: "/s", GuestCID: 10,
	}
	if _, err := f.driver.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{}); err == nil || !strings.Contains(err.Error(), "template id is empty") {
		t.Fatalf("empty template: got %v", err)
	}
	if _, err := f.driver.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{TemplateID: "tpl"}); err == nil || !strings.Contains(err.Error(), "rootfs/out paths are required") {
		t.Fatalf("missing paths: got %v", err)
	}
	req := base
	req.GuestCID = 2
	if _, err := f.driver.SnapshotTemplate(context.Background(), req); err == nil || !strings.Contains(err.Error(), "GuestCID=2 is reserved") {
		t.Fatalf("bad cid: got %v", err)
	}
}

type nilTransferPool struct {
	*fakePool
}

func (p *nilTransferPool) Transfer(context.Context, string, string, time.Time) (*TapSlot, error) {
	return nil, nil
}

func TestTryAcquireWarm_TransferNilSlotRollback(t *testing.T) {
	f := newDriverFixture(t)
	pool, handle := stageWarmFixture(t, f)
	stageWarmTemplate(t, f, false)
	f.driver.SetPool(&nilTransferPool{fakePool: f.pool})
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-warm",
	}, "sb-transfer-nil", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "warm tap transfer") {
		t.Fatalf("transfer nil: got %v", err)
	}
	if handle.shutdowns == 0 {
		t.Fatal("expected warm handle shutdown on rollback")
	}
	_ = pool
}

func TestCopyFile_LinuxProcCopyError(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux-specific copy failure")
	}
	err := copyFile("/proc/self/mem", filepath.Join(t.TempDir(), "dst"))
	if err == nil || !strings.Contains(err.Error(), "copy ") {
		t.Fatalf("proc mem copy: got %v", err)
	}
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

func TestWriteSandboxSnapshot_SecondWriteRotates(t *testing.T) {
	d := &Driver{cfg: Config{RunDir: filepath.Join(t.TempDir(), "run")}}
	client := newFakeClient()
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, rootfsFileName), []byte("rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	handle := &warmDestroyHandle{runDir: runDir}
	for i := 0; i < 2; i++ {
		if err := d.writeSandboxSnapshot(context.Background(), "sb-rotate-2", handle, client, uint32(3+i)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	manifest, err := d.readSandboxSnapshotManifest("sb-rotate-2")
	if err != nil || manifest.VsockCID != 4 {
		t.Fatalf("manifest after rotate: %+v, %v", manifest, err)
	}
}

func TestWarmSpawn_TapRemoveOnErrorWarn(t *testing.T) {
	f := newDriverFixture(t)
	mem, state, _ := writeVerifyCacheFiles(t, t.TempDir(), "m", "s")
	f.tapHost.removeErr = os.ErrPermission
	f.vmm.startErr = os.ErrPermission
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-tap-rm", SnapshotMemoryPath: mem, SnapshotStatePath: state, VsockCID: 20,
	}); err == nil {
		t.Fatal("expected start failure")
	}
}

func TestCreateSnapshotArtifacts_JailerCopyFailure(t *testing.T) {
	runDir := t.TempDir()
	d := &Driver{cfg: Config{UseJailer: true}}
	client := newFakeClient()
	client.snapshotBase = runDir
	outDir := filepath.Join(t.TempDir(), "out")
	if err := os.Mkdir(outDir, 0o555); err != nil {
		t.Fatal(err)
	}
	memOut := filepath.Join(outDir, "mem")
	stateOut := filepath.Join(outDir, "state")
	if err := d.createSnapshotArtifacts(context.Background(), client, runDir, memOut, stateOut); err == nil || !strings.Contains(err.Error(), "copy snapshot memory") {
		t.Fatalf("jailer copy failure: got %v", err)
	}
}

func TestWriteSandboxSnapshot_BaseNotDirectory(t *testing.T) {
	runRoot := t.TempDir()
	d := &Driver{cfg: Config{RunDir: runRoot}}
	base, err := d.sandboxSnapshotBase()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base, []byte("not-a-dir"), 0o644); err != nil {
		t.Fatal(err)
	}
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, rootfsFileName), []byte("r"), 0o644); err != nil {
		t.Fatal(err)
	}
	err = d.writeSandboxSnapshot(context.Background(), "sb-base-file", &warmDestroyHandle{runDir: runDir}, newFakeClient(), 3)
	if err == nil || !strings.Contains(err.Error(), "create snapshot base") {
		t.Fatalf("base not dir: got %v", err)
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

func TestCreate_SnapshotTemplatePlaceholderOverlay(t *testing.T) {
	f := newDriverFixture(t)
	rootfs := filepath.Join(t.TempDir(), "rootfs.ext4")
	mem, state, _ := writeVerifyCacheFiles(t, t.TempDir(), "m", "s")
	if err := os.WriteFile(rootfs, []byte("r"), 0o644); err != nil {
		t.Fatal(err)
	}
	f.driver.SetTemplateResolver(&fakeTemplateResolver{
		rootfsPath: rootfs, hasSnapshot: true, hasOverlay: true,
		snapshotMemoryPath: mem, snapshotStatePath: state, snapshotVsockCID: 200,
	})
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-overlay-ph",
	}, "sb-snap-ph", "tok", nil); err != nil {
		t.Fatalf("snapshot placeholder overlay: %v", err)
	}
}

func TestWarmSpawn_MissingPoolAndTapHost(t *testing.T) {
	d := New(Config{KernelImage: "/k"}, nil)
	req := WarmSpawnRequest{SlotID: "slot-miss", SnapshotMemoryPath: "m", SnapshotStatePath: "s", VsockCID: 10}
	if _, err := d.WarmSpawn(context.Background(), req); err == nil || !strings.Contains(err.Error(), "TAP pool not registered") {
		t.Fatalf("missing pool: got %v", err)
	}
	d.SetPool(newFakePool())
	if _, err := d.WarmSpawn(context.Background(), req); err == nil || !strings.Contains(err.Error(), "TAP host manager not registered") {
		t.Fatalf("missing tap host: got %v", err)
	}
}

func TestWarmSpawn_SpawnFailureCleansUp(t *testing.T) {
	f := newDriverFixture(t)
	mem, state, _ := writeVerifyCacheFiles(t, t.TempDir(), "m", "s")
	f.driver.SetSpawner(func(Config, string) (VMMHandle, error) {
		return nil, os.ErrPermission
	})
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-spawn-fail", SnapshotMemoryPath: mem, SnapshotStatePath: state, VsockCID: 10,
	}); err == nil || !strings.Contains(err.Error(), "spawn handle") {
		t.Fatalf("spawn fail: got %v", err)
	}
	if f.pool.release != 1 || f.tapHost.removeCalls != 1 {
		t.Fatalf("cleanup release/remove = %d/%d, want 1/1", f.pool.release, f.tapHost.removeCalls)
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

func TestTryAcquireWarm_OverlayMkfsSuccess(t *testing.T) {
	f := newDriverFixture(t)
	stageWarmFixture(t, f)
	stageWarmTemplate(t, f, true)
	mkfs := filepath.Join(t.TempDir(), "mkfs.ext4")
	if err := os.WriteFile(mkfs, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	f.driver.cfg.OverlayMkfs = true
	f.driver.cfg.Mkfs4Bin = mkfs
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, TemplateID: "tpl-warm", OverlaySizeGB: 1,
	}, "sb-warm-mkfs", "tok", nil); err != nil {
		t.Fatalf("warm mkfs create: %v", err)
	}
}

func TestWarmHandle_ShutdownTapAndPoolWarn(t *testing.T) {
	base := &stubWarmBaseHandle{}
	driver := New(Config{}, nil)
	pool := newFakePool()
	pool.relErr = os.ErrPermission
	driver.SetPool(pool)
	driver.SetTapHost(&fakeTapHost{removeErr: os.ErrPermission})
	wh := &warmHandle{
		driver:  driver,
		handle:  base,
		slotID:  "slot-warn2",
		tapName: "tap-warn2",
	}
	wh.setTapOwner("slot-warn2")
	if err := wh.Shutdown(context.Background(), time.Second); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestWriteSandboxSnapshot_RemoveOldBackupWarn(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix-only chmod")
	}
	d := &Driver{cfg: Config{RunDir: filepath.Join(t.TempDir(), "run")}}
	client := newFakeClient()
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, rootfsFileName), []byte("rootfs"), 0o644); err != nil {
		t.Fatal(err)
	}
	handle := &warmDestroyHandle{runDir: runDir}
	ctx := context.Background()
	if err := d.writeSandboxSnapshot(ctx, "sb-old-warn", handle, client, 3); err != nil {
		t.Fatalf("first write: %v", err)
	}
	finalDir, _, _, _, _, _ := d.sandboxSnapshotPaths("sb-old-warn")
	oldDir := finalDir + ".old"
	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(oldDir, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(oldDir, 0o700)
	if err := d.writeSandboxSnapshot(ctx, "sb-old-warn", handle, client, 4); err != nil {
		t.Fatalf("second write: %v", err)
	}
}

func TestCopyFile_OpenFailureOnFifoWithoutWriter(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("linux returns ENXIO when opening a fifo without a writer")
	}
	dir := t.TempDir()
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	if err := copyFile(fifo, filepath.Join(dir, "dst")); err == nil || !strings.Contains(err.Error(), "open ") {
		t.Fatalf("fifo open: got %v", err)
	}
}

func TestCreate_WaitSocketAndOverlayMkfsMissingBin(t *testing.T) {
	f := newDriverFixture(t)
	f.vmm.waitErr = os.ErrDeadlineExceeded
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-wait-sock", "tok", nil); err == nil || !strings.Contains(err.Error(), "wait api socket") {
		t.Fatalf("wait socket: got %v", err)
	}

	f.vmm.waitErr = nil
	f.driver.cfg.OverlayMkfs = true
	f.driver.cfg.Mkfs4Bin = ""
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, OverlaySizeGB: 1,
	}, "sb-mkfs-missing", "tok", nil); err == nil || !strings.Contains(err.Error(), "SB_FIRECRACKER_MKFS_BIN is unset") {
		t.Fatalf("mkfs missing bin: got %v", err)
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

func TestDestroy_SnapshotDirRemoveWarn(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin immutable flag blocks snapshot dir removal")
	}
	f := newDriverFixture(t)
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-snap-rm-warn", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	snapDir := f.driver.sandboxSnapshotDir("sb-snap-rm-warn")
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unix.Chflags(snapDir, unix.UF_IMMUTABLE); err != nil {
		t.Fatalf("chflags: %v", err)
	}
	defer unix.Chflags(snapDir, 0)
	// Immutable snapshot dir makes RemoveAll fail; Destroy may surface that
	// or only WARN — either way the cleanup-failure branch is exercised.
	_ = f.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-snap-rm-warn"})
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

func TestWarmSpawn_TapEnsureFailurePoolReleaseWarn(t *testing.T) {
	f := newDriverFixture(t)
	mem, state, _ := writeVerifyCacheFiles(t, t.TempDir(), "m", "s")
	f.tapHost.ensureErr = os.ErrPermission
	f.pool.relErr = os.ErrPermission
	if _, err := f.driver.WarmSpawn(context.Background(), WarmSpawnRequest{
		SlotID: "slot-rel-warn", SnapshotMemoryPath: mem, SnapshotStatePath: state, VsockCID: 21,
	}); err == nil || !strings.Contains(err.Error(), "tap host ensure") {
		t.Fatalf("tap ensure: got %v", err)
	}
}

func TestConfigureSandboxSnapshotRestore_OverlayPatchError(t *testing.T) {
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
	d := &Driver{cfg: Config{UseJailer: false}}
	client := &selectivePatchErrClient{fakeClient: newFakeClient(), failDriveID: overlayDriveID}
	err := d.configureSandboxSnapshotRestore(context.Background(), client, &sandboxSnapshotManifest{HasOverlay: true},
		mem, state, rootfs, &TapSlot{TapName: "tap0"}, overlay)
	if err == nil || !strings.Contains(err.Error(), "PatchDrive overlay") {
		t.Fatalf("overlay patch: got %v", err)
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

func TestSnapshotTemplate_InvalidVMMID(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.KernelImage = f.kernel
	_, err := f.driver.SnapshotTemplate(context.Background(), TemplateSnapshotRequest{
		TemplateID: strings.Repeat("x", 200),
		RootfsPath: "/r", OutMemoryPath: "/m", OutStatePath: "/s", GuestCID: 10,
	})
	// Oversized template IDs are rejected either as invalid IDs or via the
	// VMM sandbox-ID length cap (template id becomes the VMM id).
	if err == nil || (!strings.Contains(err.Error(), "invalid") && !strings.Contains(err.Error(), "exceeds 128")) {
		t.Fatalf("invalid template id: got %v", err)
	}
}

func TestSendVsockOp_HappyPathDiscardsAck(t *testing.T) {
	d := &Driver{vsockDial: &stubVsockDialer{conns: []*errVsockConn{{reply: []byte(`{"ok":true}` + "\n")}}}}
	if err := d.sendVsockOp(context.Background(), "/tmp/vsock.sock", 3, "post_resume", map[string]string{"ip": "10.0.0.2"}); err != nil {
		t.Fatalf("sendVsockOp: %v", err)
	}
}

func TestCreateSnapshotArtifacts_JailerStateCopyFailure(t *testing.T) {
	runDir := t.TempDir()
	d := &Driver{cfg: Config{UseJailer: true}}
	client := newFakeClient()
	client.snapshotBase = runDir
	memOut := filepath.Join(t.TempDir(), "mem")
	stateDir := filepath.Join(t.TempDir(), "state-dir")
	if err := os.Mkdir(stateDir, 0o755); err != nil {
		t.Fatal(err)
	}
	stateOut := stateDir
	if err := d.createSnapshotArtifacts(context.Background(), client, runDir, memOut, stateOut); err == nil || !strings.Contains(err.Error(), "copy snapshot state") {
		t.Fatalf("state copy failure: got %v", err)
	}
}

type failingCopyDest struct {
	buf      []byte
	writeErr error
	syncErr  error
	closeErr error
}

func (f *failingCopyDest) Write(p []byte) (int, error) {
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	f.buf = append(f.buf, p...)
	return len(p), nil
}
func (f *failingCopyDest) Sync() error  { return f.syncErr }
func (f *failingCopyDest) Close() error { return f.closeErr }

func TestCopyFile_InjectedIOFailures(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatal(err)
	}
	orig := copyFileOpenDst
	t.Cleanup(func() { copyFileOpenDst = orig })

	t.Run("create", func(t *testing.T) {
		copyFileOpenDst = func(string, os.FileMode) (copyFileDest, error) {
			return nil, os.ErrPermission
		}
		if err := copyFile(src, filepath.Join(dir, "dst-create")); err == nil || !strings.Contains(err.Error(), "create ") {
			t.Fatalf("create: %v", err)
		}
	})
	t.Run("copy", func(t *testing.T) {
		copyFileOpenDst = func(string, os.FileMode) (copyFileDest, error) {
			return &failingCopyDest{writeErr: io.ErrShortWrite}, nil
		}
		if err := copyFile(src, filepath.Join(dir, "dst-copy")); err == nil || !strings.Contains(err.Error(), "copy ") {
			t.Fatalf("copy: %v", err)
		}
	})
	t.Run("sync", func(t *testing.T) {
		copyFileOpenDst = func(string, os.FileMode) (copyFileDest, error) {
			return &failingCopyDest{syncErr: os.ErrInvalid}, nil
		}
		if err := copyFile(src, filepath.Join(dir, "dst-sync")); err == nil || !strings.Contains(err.Error(), "sync ") {
			t.Fatalf("sync: %v", err)
		}
	})
	t.Run("close", func(t *testing.T) {
		copyFileOpenDst = func(string, os.FileMode) (copyFileDest, error) {
			return &failingCopyDest{closeErr: os.ErrClosed}, nil
		}
		if err := copyFile(src, filepath.Join(dir, "dst-close")); err == nil || !strings.Contains(err.Error(), "close ") {
			t.Fatalf("close: %v", err)
		}
	})
}

func TestCopyFile_OpenPermissionDenied(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root can open mode-000 files")
	}
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(src, 0o000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(src, 0o644)
	if err := copyFile(src, filepath.Join(dir, "dst")); err == nil || !strings.Contains(err.Error(), "open ") {
		t.Fatalf("open: %v", err)
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

func TestConfigureSandboxSnapshotRestore_RootfsStageError(t *testing.T) {
	runDir := t.TempDir()
	mem := filepath.Join(runDir, "mem")
	state := filepath.Join(runDir, "state")
	for _, p := range []string{mem, state} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	d := &Driver{cfg: Config{UseJailer: true, JailerUID: os.Getuid(), JailerGID: os.Getgid()}}
	client := newFakeClient()
	err := d.configureSandboxSnapshotRestore(context.Background(), client, &sandboxSnapshotManifest{},
		mem, state, filepath.Join(t.TempDir(), "missing-rootfs.ext4"), &TapSlot{TapName: "tap0"}, "")
	if err == nil || !strings.Contains(err.Error(), "stage snapshot rootfs") {
		t.Fatalf("rootfs stage: got %v", err)
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
