package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	vmmpool "github.com/aerol-ai/microvm/internal/pool/vmm"
	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

type runningClient struct{ fakeClient }

func (c *runningClient) InstanceInfo(context.Context) (*firecracker.InstanceInfo, error) {
	return &firecracker.InstanceInfo{State: "Running"}, nil
}

func TestNew_NilLoggerAndDefaultSeams(t *testing.T) {
	d := New(Config{FirecrackerBinary: "/fc", RunDir: t.TempDir()}, nil)
	if d.logger == nil {
		t.Fatal("New(nil logger) should default to slog.Default()")
	}
	if _, err := d.spawn(Config{}, "sb"); err == nil {
		t.Fatal("default spawn should delegate to newVMM and reject empty FirecrackerBinary")
	}
	if d.newClient(t.TempDir()+"/api.sock") == nil {
		t.Fatal("default newClient returned nil")
	}
}

func TestRootfsResult_CleanupIdempotent(t *testing.T) {
	calls := 0
	r := NewRootfsResult("/rootfs", "/staging", 42, func() error {
		calls++
		return errors.New("cleanup failed")
	})
	if err := r.Cleanup(); err == nil {
		t.Fatal("expected cleanup error")
	}
	if calls != 1 {
		t.Fatalf("cleanup calls = %d, want 1", calls)
	}
	if err := r.Cleanup(); err != nil {
		t.Fatalf("second Cleanup should be no-op, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("cleanup calls after second call = %d, want 1", calls)
	}
	if (*RootfsResult)(nil).Cleanup() != nil {
		t.Fatal("nil RootfsResult.Cleanup should be no-op")
	}
}

func TestCopyFile_HappyPath(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("copy-me"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "copy-me" {
		t.Fatalf("dst = %q, %v", got, err)
	}
}

func TestLinkOrCopyRootfs_CopyFallbackSuccess(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	src := filepath.Join(srcDir, "rootfs.ext4")
	dst := filepath.Join(dstDir, "rootfs.ext4")
	if err := os.WriteFile(src, []byte("rootfs-copy"), 0o600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	probe := filepath.Join(dstDir, "probe")
	if err := os.Link(src, probe); err == nil {
		_ = os.Remove(probe)
		if runtime.GOOS != "linux" {
			t.Skip("same filesystem; cross-device copy fallback needs linux tmpfs")
		}
		src = filepath.Join("/dev/shm", "fc-linktest-"+filepath.Base(srcDir))
		if err := os.WriteFile(src, []byte("rootfs-copy"), 0o600); err != nil {
			t.Fatalf("write shm src: %v", err)
		}
		defer os.Remove(src)
	}

	if err := linkOrCopyRootfs(src, dst); err != nil {
		t.Fatalf("linkOrCopyRootfs: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "rootfs-copy" {
		t.Fatalf("dst = %q, %v", got, err)
	}
}

func writeFakeJailer(t *testing.T, dir, fcBin string) string {
	t.Helper()
	path := filepath.Join(dir, "jailer")
	script := "#!/bin/sh\n" +
		"while [ \"$1\" != \"--\" ] && [ $# -gt 0 ]; do shift; done\n" +
		"shift\n" +
		"exec " + shellQuote(fcBin) + " \"$@\"\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake jailer: %v", err)
	}
	return path
}

func writeFakeFirecrackerIgnoreTERM(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "firecracker")
	script := "#!/bin/sh\n" +
		"trap '' TERM INT\n" +
		"sock=\"\"\n" +
		"while [ $# -gt 0 ]; do\n" +
		"  case \"$1\" in\n" +
		"    --api-sock) sock=\"$2\"; shift 2 ;;\n" +
		"    *) shift ;;\n" +
		"  esac\n" +
		"done\n" +
		"if [ -n \"$sock\" ]; then : > \"$sock\"; fi\n" +
		"sleep 60 &\n" +
		"wait\n"
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake firecracker: %v", err)
	}
	return path
}

func TestVMM_StartViaJailer(t *testing.T) {
	dir := t.TempDir()
	chrootBase := filepath.Join(dir, "jailer-root")
	fcBin := writeFakeFirecracker(t, dir, fakeOpts{})
	jailerBin := writeFakeJailer(t, dir, fcBin)

	v, err := newVMM(Config{
		FirecrackerBinary: fcBin,
		UseJailer:         true,
		JailerBinary:      jailerBin,
		JailerChrootBase:  chrootBase,
		JailerUID:         os.Getuid(),
		JailerGID:         os.Getgid(),
	}, "sb-jailer-start", nil)
	if err != nil {
		t.Fatalf("newVMM: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := v.Start(ctx); err != nil {
		t.Fatalf("Start via jailer: %v (stderr: %s)", err, v.StderrTail())
	}
	if err := v.WaitSocket(ctx, 10*time.Second); err != nil {
		t.Fatalf("WaitSocket: %v (stderr: %s)", err, v.StderrTail())
	}
	if tail := v.StderrTail(); tail != "" && strings.Contains(tail, "error") {
		t.Logf("stderr tail: %s", tail)
	}
	if err := v.Shutdown(ctx, time.Second); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestVMM_ShutdownEscalatesToSIGKILL(t *testing.T) {
	dir := t.TempDir()
	fcBin := writeFakeFirecrackerIgnoreTERM(t, dir)
	cfg := Config{FirecrackerBinary: fcBin, RunDir: dir}
	v, err := newVMM(cfg, "sb-kill-escalate", nil)
	if err != nil {
		t.Fatalf("newVMM: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := v.Start(ctx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := v.WaitSocket(ctx, 10*time.Second); err != nil {
		t.Fatalf("WaitSocket: %v", err)
	}
	if err := v.Shutdown(ctx, 50*time.Millisecond); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
}

func TestVMM_ShutdownContextCanceled(t *testing.T) {
	dir := t.TempDir()
	fcBin := writeFakeFirecrackerIgnoreTERM(t, dir)
	v, err := newVMM(Config{FirecrackerBinary: fcBin, RunDir: dir}, "sb-shutdown-ctx", nil)
	if err != nil {
		t.Fatalf("newVMM: %v", err)
	}
	startCtx, startCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer startCancel()
	if err := v.Start(startCtx); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := v.WaitSocket(startCtx, 10*time.Second); err != nil {
		t.Fatalf("WaitSocket: %v", err)
	}
	shutdownCtx, shutdownCancel := context.WithCancel(context.Background())
	shutdownCancel()
	if err := v.Shutdown(shutdownCtx, 5*time.Second); !errors.Is(err, context.Canceled) {
		t.Fatalf("Shutdown: got %v, want context.Canceled", err)
	}
	_ = v.Kill()
}

func TestReadSandboxSnapshotManifest_ValidationAndRecovery(t *testing.T) {
	d := &Driver{cfg: Config{RunDir: t.TempDir()}}
	sbID := "sb-manifest"

	dir, _, _, _, _, manifestPath := d.sandboxSnapshotPaths(sbID)

	writeManifest := func(m sandboxSnapshotManifest) {
		t.Helper()
		raw, err := json.Marshal(m)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
			t.Fatalf("write manifest: %v", err)
		}
	}

	if _, err := d.readSandboxSnapshotManifest(sbID); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing manifest: got %v", err)
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	oldDir := dir + ".old"
	_ = os.RemoveAll(dir)
	if err := os.MkdirAll(oldDir, 0o700); err != nil {
		t.Fatalf("mkdir old: %v", err)
	}
	oldManifest := filepath.Join(oldDir, sandboxSnapshotManifestName)
	raw, _ := json.Marshal(sandboxSnapshotManifest{
		Version: 1, SandboxID: sbID, VsockCID: 3, SnapshotChecksum: "sha256:aa|sha256:bb",
	})
	if err := os.WriteFile(oldManifest, raw, 0o600); err != nil {
		t.Fatalf("write old manifest: %v", err)
	}
	got, err := d.readSandboxSnapshotManifest(sbID)
	if err != nil {
		t.Fatalf("recover from .old: %v", err)
	}
	if got.SandboxID != sbID || got.VsockCID != 3 {
		t.Fatalf("recovered manifest = %+v", got)
	}

	writeManifest(sandboxSnapshotManifest{Version: 2, SandboxID: sbID, VsockCID: 3})
	if _, err := d.readSandboxSnapshotManifest(sbID); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("version mismatch: got %v", err)
	}

	writeManifest(sandboxSnapshotManifest{Version: 1, SandboxID: "other", VsockCID: 3})
	if _, err := d.readSandboxSnapshotManifest(sbID); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Fatalf("sandbox id mismatch: got %v", err)
	}

	writeManifest(sandboxSnapshotManifest{Version: 1, SandboxID: sbID, VsockCID: 2})
	if _, err := d.readSandboxSnapshotManifest(sbID); err == nil || !strings.Contains(err.Error(), "reserved vsock CID") {
		t.Fatalf("cid mismatch: got %v", err)
	}
}

func TestStopToSandboxSnapshot_IdempotentWhenManifestExists(t *testing.T) {
	d := &Driver{
		cfg:     Config{RunDir: t.TempDir()},
		pool:    newFakePool(),
		tapHost: &fakeTapHost{},
	}
	sbID := "sb-stopped"
	dir, memPath, statePath, rootfsPath, _, manifestPath := d.sandboxSnapshotPaths(sbID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, p := range []string{memPath, statePath, rootfsPath, manifestPath} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	raw, _ := json.Marshal(sandboxSnapshotManifest{
		Version: 1, SandboxID: sbID, VsockCID: 3, SnapshotChecksum: "sha256:aa|sha256:bb",
	})
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := d.stopToSandboxSnapshot(context.Background(), sbID); err != nil {
		t.Fatalf("idempotent stop: %v", err)
	}
}

type errVsockConn struct {
	dialErr  error
	writeErr error
	readErr  error
	reply    []byte
}

func (c *errVsockConn) Read(p []byte) (int, error) {
	if c.readErr != nil {
		return 0, c.readErr
	}
	if len(c.reply) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.reply)
	c.reply = c.reply[n:]
	return n, nil
}

func (c *errVsockConn) Write(p []byte) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	return len(p), nil
}

func (c *errVsockConn) Close() error { return nil }

type stubVsockDialer struct {
	mu    sync.Mutex
	conns []*errVsockConn
	err   error
	idx   int
}

func (d *stubVsockDialer) Dial(_ context.Context, _, _ uint32) (io.ReadWriteCloser, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.err != nil {
		return nil, d.err
	}
	if d.idx >= len(d.conns) {
		return nil, errors.New("no more conns")
	}
	c := d.conns[d.idx]
	d.idx++
	return c, nil
}

func TestVsockHandshake_ErrorPaths(t *testing.T) {
	d := &Driver{vsockDial: &stubVsockDialer{
		conns: []*errVsockConn{
			{writeErr: errors.New("write failed")},
			{reply: []byte(`{"ok":true}`)}, // unused
		},
	}}
	if err := d.vsockHandshake(context.Background(), 3); err == nil || !strings.Contains(err.Error(), "vsock write") {
		t.Fatalf("write error: got %v", err)
	}

	d.vsockDial = &stubVsockDialer{conns: []*errVsockConn{{readErr: io.EOF}}}
	if err := d.vsockHandshake(context.Background(), 3); err == nil || !strings.Contains(err.Error(), "vsock read") {
		t.Fatalf("read error: got %v", err)
	}

	d.vsockDial = &stubVsockDialer{conns: []*errVsockConn{{reply: []byte("not-json\n")}}}
	if err := d.vsockHandshake(context.Background(), 3); err == nil || !strings.Contains(err.Error(), "vsock decode") {
		t.Fatalf("decode error: got %v", err)
	}

	d.vsockDial = &stubVsockDialer{conns: []*errVsockConn{{reply: []byte(`{"ok":false}` + "\n")}}}
	if err := d.vsockHandshake(context.Background(), 3); err == nil || !strings.Contains(err.Error(), "guest returned ok=false") {
		t.Fatalf("ok=false empty error: got %v", err)
	}

	shortCtx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
	defer cancel()
	time.Sleep(2 * time.Millisecond)
	d.vsockDial = &stubVsockDialer{err: errors.New("dial refused")}
	if err := d.vsockHandshake(shortCtx, 3); err == nil {
		t.Fatal("expected deadline exceeded on short ctx")
	}
}

func TestSendVsockOp_WithPayload(t *testing.T) {
	d := &Driver{vsockDial: &stubVsockDialer{conns: []*errVsockConn{{reply: []byte("ignored\n")}}}}
	if err := d.sendVsockOp(context.Background(), 3, "pre_snapshot", map[string]string{"phase": "stop"}); err != nil {
		t.Fatalf("sendVsockOp: %v", err)
	}
}

func TestSendVsockOp_DialAndWriteErrors(t *testing.T) {
	d := &Driver{vsockDial: &stubVsockDialer{err: errors.New("dial down")}}
	if err := d.sendVsockOp(context.Background(), 3, "ping", nil); err == nil || !strings.Contains(err.Error(), "dial cid") {
		t.Fatalf("dial error: got %v", err)
	}

	d.vsockDial = &stubVsockDialer{conns: []*errVsockConn{{writeErr: errors.New("write down")}}}
	if err := d.sendVsockOp(context.Background(), 3, "ping", nil); err == nil || !strings.Contains(err.Error(), "write") {
		t.Fatalf("write error: got %v", err)
	}
}

func TestInspect_ReturnsRunningStatus(t *testing.T) {
	d := New(Config{}, nil)
	d.mu.Lock()
	d.clients["sb-run"] = &runningClient{}
	d.mu.Unlock()
	state, err := d.Inspect(context.Background(), "sb-run")
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if state == nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("state = %+v, want started", state)
	}
}

func TestStopToSandboxSnapshot_ShutdownFailsKillSucceeds(t *testing.T) {
	f := newDriverFixture(t)
	ctx := context.Background()
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-stop-kill", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.vmm.shutdownErr = errors.New("shutdown failed")
	if err := f.driver.Stop(ctx, "sb-stop-kill"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	_, _, _, _, _, manifestPath := f.driver.sandboxSnapshotPaths("sb-stop-kill")
	if _, err := os.Stat(manifestPath); err != nil {
		t.Fatalf("expected snapshot after shutdown failure + kill: %v", err)
	}
}

func TestHashFile_ReadError(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := hashFile(dir); err == nil || !strings.Contains(err.Error(), "read ") {
		t.Fatalf("expected read error for directory, got %v", err)
	}
}

func TestDestroy_WarmPoolReleaseAndSnapshotDir(t *testing.T) {
	f := newDriverFixture(t)
	pool := &fakeWarmPool{}
	f.driver.SetWarmPool(pool)

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-warm-destroy", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	snapDir := f.driver.sandboxSnapshotDir("sb-warm-destroy")
	if err := os.MkdirAll(snapDir, 0o700); err != nil {
		t.Fatalf("mkdir snapshot dir: %v", err)
	}

	if err := f.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-warm-destroy"}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	pool.mu.Lock()
	defer pool.mu.Unlock()
	if len(pool.releaseCalls) != 1 {
		t.Fatalf("warm pool release calls = %d, want 1", len(pool.releaseCalls))
	}
	if _, err := os.Stat(snapDir); !os.IsNotExist(err) {
		t.Fatalf("snapshot dir still exists: %v", err)
	}
}

func TestDriver_Create_SynthIDAndOverlayBounds(t *testing.T) {
	f := newDriverFixture(t)

	state, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "", "tok", nil)
	if err != nil {
		t.Fatalf("Create with empty sandbox ID: %v", err)
	}
	if state == nil || state.SandboxID == "" {
		t.Fatalf("expected synthesized sandbox ID, got %+v", state)
	}

	_, err = f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, OverlaySizeGB: -1,
	}, "sb-overlay-bad", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "out of range") {
		t.Fatalf("overlay bounds: got %v", err)
	}
}

func TestPoolSpawner_SpawnPropagatesWarmSpawnError(t *testing.T) {
	d := New(Config{}, nil)
	adapter := NewPoolSpawner(d)
	if _, err := adapter.Spawn(context.Background(), "slot", vmmpool.SnapshotInputs{}); err == nil {
		t.Fatal("expected WarmSpawn error from empty config")
	}
}

func TestCreate_MissingSeamPreconditions(t *testing.T) {
	req := models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 128}
	ctx := context.Background()

	cases := []struct {
		name string
		mut  func(*driverFixture)
		want string
	}{
		{
			name: "rootfs",
			mut:  func(f *driverFixture) { f.driver.rootfs = nil },
			want: "rootfs builder not registered",
		},
		{
			name: "tap host",
			mut:  func(f *driverFixture) { f.driver.tapHost = nil },
			want: "TAP host manager not registered",
		},
		{
			name: "vsock dialer",
			mut:  func(f *driverFixture) { f.driver.vsockDial = nil },
			want: "vsock dialer not registered",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDriverFixture(t)
			tc.mut(f)
			_, err := f.driver.Create(ctx, req, "sb-missing-"+tc.name, "tok", nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Create: got %v, want %q", err, tc.want)
			}
		})
	}
}

func TestDestroy_PoolAndCleanupErrors(t *testing.T) {
	f := newDriverFixture(t)
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-destroy-errs2", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	f.pool.getErr = os.ErrPermission
	f.pool.relErr = os.ErrPermission
	f.vmm.cleanupErr = os.ErrPermission
	snapDir := f.driver.sandboxSnapshotDir("sb-destroy-errs2")
	if err := os.MkdirAll(filepath.Dir(snapDir), 0o755); err != nil {
		t.Fatalf("mkdir snap parent: %v", err)
	}
	if err := os.WriteFile(snapDir, []byte("not-a-dir"), 0o600); err != nil {
		t.Fatalf("write snap blocker: %v", err)
	}

	err = f.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-destroy-errs2"})
	if err == nil {
		t.Fatal("expected first destroy error")
	}
}

func TestDestroy_WarmPoolReleaseError(t *testing.T) {
	f := newDriverFixture(t)
	pool := &fakeWarmPool{releaseErr: os.ErrPermission}
	f.driver.SetWarmPool(pool)
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-warm-rel-err", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := f.driver.Destroy(context.Background(), &models.Sandbox{ID: "sb-warm-rel-err"}); err == nil {
		t.Fatal("expected warm pool release error")
	}
}

func TestStop_PreSnapshotFailureUsesSlotCID(t *testing.T) {
	f := newDriverFixture(t)
	ctx := context.Background()
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-stop-cid", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.driver.mu.Lock()
	delete(f.driver.guestCID, "sb-stop-cid")
	f.driver.mu.Unlock()
	f.vsock.err = errors.New("pre_snapshot dial failed")

	if err := f.driver.Stop(ctx, "sb-stop-cid"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if f.vsock.lastCID != 3 {
		t.Fatalf("pre_snapshot dialed cid=%d, want slot cid 3", f.vsock.lastCID)
	}
}

func TestStop_ReplacesExistingSnapshot(t *testing.T) {
	f := newDriverFixture(t)
	ctx := context.Background()
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-stop-rotate", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	finalDir, _, _, _, _, _ := f.driver.sandboxSnapshotPaths("sb-stop-rotate")
	if err := os.MkdirAll(finalDir, 0o700); err != nil {
		t.Fatalf("mkdir final: %v", err)
	}
	if err := os.WriteFile(filepath.Join(finalDir, sandboxSnapshotManifestName), []byte("stale"), 0o600); err != nil {
		t.Fatalf("write stale manifest: %v", err)
	}
	if err := f.driver.Stop(ctx, "sb-stop-rotate"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if _, err := f.driver.readSandboxSnapshotManifest("sb-stop-rotate"); err != nil {
		t.Fatalf("read rotated manifest: %v", err)
	}
}

func TestStop_InvalidSandboxID(t *testing.T) {
	f := newDriverFixture(t)
	if err := f.driver.Stop(context.Background(), "bad/id"); err == nil || !strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("expected invalid sandbox id error, got %v", err)
	}
}

func TestStop_TapRemoveWarnPath(t *testing.T) {
	f := newDriverFixture(t)
	ctx := context.Background()
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-stop-tap-warn", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.tapHost.removeErr = os.ErrPermission
	if err := f.driver.Stop(ctx, "sb-stop-tap-warn"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestStop_VMMCleanupWarnPath(t *testing.T) {
	f := newDriverFixture(t)
	ctx := context.Background()
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-stop-cleanup", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	f.vmm.cleanupErr = os.ErrPermission
	if err := f.driver.Stop(ctx, "sb-stop-cleanup"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
}

func TestCreate_WarmHitWithOverlay(t *testing.T) {
	f := newDriverFixture(t)
	stageWarmFixture(t, f)
	stageWarmTemplate(t, f, true)
	f.driver.cfg.OverlayEnabled = true

	state, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:         "alpine:3.20",
		CPU:           1,
		MemoryMB:      128,
		DiskGB:        1,
		TemplateID:    "tpl-warm",
		OverlaySizeGB: 1,
	}, "sb-warm-overlay", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if state == nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("state = %+v", state)
	}
	if patch, ok := f.client.drivePatches[overlayDriveID]; !ok || patch.PathOnHost == "" {
		t.Fatalf("overlay patch missing: %+v", f.client.drivePatches)
	}
}

func TestCreate_WarmRollbackReleaseError(t *testing.T) {
	f := newDriverFixture(t)
	pool, _ := stageWarmFixture(t, f)
	stageWarmTemplate(t, f, false)
	pool.releaseErr = os.ErrPermission
	f.client.networkPatchErr = errors.New("patch nic failed")

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:      "alpine:3.20",
		CPU:        1,
		MemoryMB:   128,
		DiskGB:     1,
		TemplateID: "tpl-warm",
	}, "sb-warm-rel-warn", "tok", nil)
	if err == nil {
		t.Fatal("expected create failure")
	}
}

func TestLinkOrCopyRootfs_PermissionFallbackCopy(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	src := filepath.Join(srcDir, "rootfs.ext4")
	dst := filepath.Join(dstDir, "rootfs.ext4")
	if err := os.WriteFile(src, []byte("perm-fallback"), 0o000); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := linkOrCopyRootfs(src, dst); err != nil {
		t.Fatalf("linkOrCopyRootfs: %v", err)
	}
	if err := os.Chmod(dst, 0o644); err != nil {
		t.Fatalf("chmod dst: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil || string(got) != "perm-fallback" {
		t.Fatalf("dst = %q, %v", got, err)
	}
}

func TestStart_ReturnsStateWhenVMMAlreadyRunning(t *testing.T) {
	f := newDriverFixture(t)
	ctx := context.Background()
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, "sb-already-running", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	state, err := f.driver.Start(ctx, "sb-already-running")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if state == nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("state = %+v", state)
	}
	if f.client.snapshotLoad != nil {
		t.Fatal("Start should not LoadSnapshot when VMM is already running")
	}
}

func TestStart_PostResumeWarnContinues(t *testing.T) {
	f := newDriverFixture(t)
	ctx := context.Background()
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1,
	}, "sb-post-resume-warn", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := f.driver.Stop(ctx, "sb-post-resume-warn"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	postResumeVsock := newFakeVsockDialer()
	postResumeVsock.errOnDialIdx = 2
	f.driver.SetVsockDialer(postResumeVsock)
	state, err := f.driver.Start(ctx, "sb-post-resume-warn")
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	if state == nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("state = %+v", state)
	}
}

func TestStartFromSandboxSnapshot_RollbackWarnPaths(t *testing.T) {
	d := &Driver{
		cfg:    Config{RunDir: filepath.Join(t.TempDir(), "run")},
		logger: slog.Default(),
	}
	d.pool = newFakePool()
	d.tapHost = &fakeTapHost{}
	d.vsockDial = newFakeVsockDialer()
	sbID := "sb-start-warn"
	dir, memPath, statePath, rootfsPath, overlayPath, manifestPath := d.sandboxSnapshotPaths(sbID)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	for _, p := range []string{memPath, statePath, rootfsPath} {
		if err := os.WriteFile(p, []byte("artifact"), 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	memD, _, _ := hashFile(memPath)
	stateD, _, _ := hashFile(statePath)
	manifest := sandboxSnapshotManifest{
		Version: 1, SandboxID: sbID, VsockCID: 3,
		SnapshotChecksum: formatSnapshotChecksum(memD, stateD),
	}
	raw, _ := json.Marshal(manifest)
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	_ = overlayPath
	d.pool.Allocate(context.Background(), sbID, time.Now())

	runDir := filepath.Join(t.TempDir(), "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatalf("mkdir run: %v", err)
	}
	d.SetSpawner(func(Config, string) (VMMHandle, error) {
		return &fakeVMM{runDir: runDir, cleanupErr: os.ErrPermission}, nil
	})
	client := newFakeClient()
	client.snapshotLoadErr = os.ErrPermission
	d.SetClientFactory(func(string) VMMClient { return client })
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil {
		t.Fatal("expected restore failure")
	}

	d.SetSpawner(func(Config, string) (VMMHandle, error) {
		return &fakeVMM{runDir: runDir}, nil
	})
	client = newFakeClient()
	client.snapshotLoadErr = os.ErrPermission
	d.SetClientFactory(func(string) VMMClient { return client })
	d.tapHost = &fakeTapHost{removeErr: os.ErrPermission}
	if _, err := d.startFromSandboxSnapshot(context.Background(), sbID); err == nil {
		t.Fatal("expected restore failure for tap-remove warn path")
	}
}

func TestWriteSandboxSnapshot_RotationPromotesSnapshot(t *testing.T) {
	d := &Driver{cfg: Config{RunDir: filepath.Join(t.TempDir(), "run")}}
	client := newFakeClient()
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, rootfsFileName), []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}
	handle := &warmDestroyHandle{runDir: runDir}
	ctx := context.Background()
	for i := 0; i < 2; i++ {
		if err := d.writeSandboxSnapshot(ctx, "sb-rotate", handle, client, 3); err != nil {
			t.Fatalf("writeSandboxSnapshot pass %d: %v", i+1, err)
		}
	}
	if _, err := d.readSandboxSnapshotManifest("sb-rotate"); err != nil {
		t.Fatalf("read manifest: %v", err)
	}
}

func TestWriteSandboxSnapshot_HappyPathWithOverlay(t *testing.T) {
	d := &Driver{cfg: Config{RunDir: filepath.Join(t.TempDir(), "run")}}
	client := newFakeClient()
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, rootfsFileName), []byte("rootfs"), 0o644); err != nil {
		t.Fatalf("write rootfs: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runDir, overlayFileName), []byte("overlay"), 0o644); err != nil {
		t.Fatalf("write overlay: %v", err)
	}
	handle := &warmDestroyHandle{runDir: runDir}
	if err := d.writeSandboxSnapshot(context.Background(), "sb-write-ok", handle, client, 42); err != nil {
		t.Fatalf("writeSandboxSnapshot: %v", err)
	}
	manifest, err := d.readSandboxSnapshotManifest("sb-write-ok")
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	if !manifest.HasOverlay || manifest.VsockCID != 42 {
		t.Fatalf("manifest = %+v", manifest)
	}
}

func TestCreate_WarmPlaceholderOverlay(t *testing.T) {
	f := newDriverFixture(t)
	stageWarmFixture(t, f)
	stageWarmTemplate(t, f, true)
	f.driver.cfg.OverlayEnabled = true

	state, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:      "alpine:3.20",
		CPU:        1,
		MemoryMB:   128,
		TemplateID: "tpl-warm",
	}, "sb-warm-placeholder", "tok", nil)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if state == nil || state.Status != models.SandboxStatusStarted {
		t.Fatalf("state = %+v", state)
	}
	if patch, ok := f.client.drivePatches[overlayDriveID]; !ok || patch.PathOnHost == "" {
		t.Fatalf("overlay patch missing: %+v", f.client.drivePatches)
	}
}

func TestCreate_WarmRollbackShutdownWarn(t *testing.T) {
	f := newDriverFixture(t)
	_, handle := stageWarmFixture(t, f)
	stageWarmTemplate(t, f, false)
	handle.shutdownErr = os.ErrPermission
	f.client.networkPatchErr = errors.New("patch nic failed")

	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image:      "alpine:3.20",
		CPU:        1,
		MemoryMB:   128,
		TemplateID: "tpl-warm",
	}, "sb-warm-shutdown-warn", "tok", nil)
	if err == nil {
		t.Fatal("expected create failure")
	}
	if handle.shutdowns == 0 {
		t.Fatal("expected rollback shutdown attempt")
	}
}
