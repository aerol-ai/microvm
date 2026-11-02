package mounts

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// pathArgvAdapter is a stand-in FUSE tool whose argv names its mount path, as
// mount-s3's does, so the sweep's /proc matcher finds it on Linux. The trailing
// ":" keeps sh alive as the parent so its own cmdline stays the matched one.
type pathArgvAdapter struct{}

func (pathArgvAdapter) Build(_ string, _ int, _ models.MountSpec, hostTarget, _ string) (adapters.Plan, error) {
	return adapters.Plan{Argv: []string{"sh", "-c", "sleep 30; :", "mount-tool", hostTarget}}, nil
}

// lockedBuffer is a log sink the test reads while the manager may still write.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func captureLogs(m *Manager) *lockedBuffer {
	logs := &lockedBuffer{}
	m.logger = slog.New(slog.NewTextHandler(logs, nil))
	return logs
}

var s3Spec = []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://bucket", Target: "/vol"}}

type mountResult struct {
	binds []ContainerBind
	err   error
}

func mountAsync(m *Manager, id string) <-chan mountResult {
	done := make(chan mountResult, 1)
	go func() {
		binds, err := m.MountAll(context.Background(), id, s3Spec)
		done <- mountResult{binds, err}
	}()
	return done
}

// UC-84 (cluster-3-mixed-secrets, sb-1497d799f8931d0e): the periodic reconcile
// sweep fired while mount-s3 was still coming up. The sandbox was not running
// yet and the manager recorded it only once every mount was ready, so the
// sweep took the half-built directory for an orphan, killed the tool and
// removed the directory, and the create waited out the full 30s mount timeout.
func TestSweepSkipsMountInProgress(t *testing.T) {
	entered := make(chan (<-chan struct{}))
	release := make(chan struct{})
	oldProbe := waitForMountProbe
	waitForMountProbe = func(_ string, _ time.Duration, exited <-chan struct{}) error {
		entered <- exited
		<-release
		return nil
	}
	t.Cleanup(func() { waitForMountProbe = oldProbe })

	m := newTestManager(t, map[models.MountType]adapters.Adapter{
		models.MountTypeS3: pathArgvAdapter{},
	})
	logs := captureLogs(m)
	const id = "sb-1497d799f8931d0e"
	hostPath := filepath.Join(m.rootDir, id, "0")

	done := mountAsync(m, id)
	t.Cleanup(func() { _ = m.UnmountAll(id) })
	exited := <-entered

	m.Sweep(map[string]struct{}{}) // the reconcile tick: nothing is running yet

	if _, err := os.Stat(hostPath); err != nil {
		close(release)
		<-done
		t.Fatalf("sweep removed the in-progress mount directory: %v", err)
	}
	// On Linux the old sweep SIGKILLed the tool through /proc; the reaper
	// would see that within milliseconds.
	select {
	case <-exited:
		close(release)
		<-done
		t.Fatal("sweep killed the in-progress mount tool")
	case <-time.After(200 * time.Millisecond):
	}
	if got := logs.String(); !strings.Contains(got, "mounts sweep: skipping, mount in progress") ||
		strings.Contains(got, "removing orphan") {
		t.Fatalf("sweep logs = %q, want only the in-progress skip", got)
	}

	close(release)
	r := <-done
	if r.err != nil {
		t.Fatalf("MountAll after the sweep: %v", r.err)
	}
	if len(r.binds) != 1 || r.binds[0].HostPath != hostPath {
		t.Fatalf("binds = %+v, want one bind at %s", r.binds, hostPath)
	}
	if _, err := os.Stat(hostPath); err != nil {
		t.Fatalf("bind source missing after MountAll returned: %v", err)
	}

	// Once tracked, the next sweep leaves it alone too.
	m.Sweep(map[string]struct{}{})
	if _, err := os.Stat(hostPath); err != nil {
		t.Fatalf("sweep removed a tracked mount: %v", err)
	}
}

// The other order: the sweep has already claimed an id (a genuine orphan from
// an earlier attempt) when a create retried with the same id calls MountAll.
// The mount must wait for the sweep, then build a fresh directory the sweep
// can no longer delete.
func TestMountAllWaitsForSweepOfSameID(t *testing.T) {
	m := newTestManager(t, nil)
	const id = "sb-retried"
	leftover := filepath.Join(m.rootDir, id, "0")
	if err := os.MkdirAll(leftover, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(leftover, "stale"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Hold the sweep inside its cleanup of id: the leftover looks like a
	// mountpoint, and its umount blocks until released.
	oldDev, oldUmount := pathDevOf, sweepUmount
	pathDevOf = func(path string) uint64 {
		if path == leftover {
			return 42
		}
		return oldDev(path)
	}
	inCleanup := make(chan struct{})
	releaseSweep := make(chan struct{})
	sweepUmount = func(string) error {
		close(inCleanup)
		<-releaseSweep
		return nil
	}
	t.Cleanup(func() { pathDevOf, sweepUmount = oldDev, oldUmount })

	built := make(chan struct{})
	m.adapters = map[models.MountType]adapters.Adapter{
		models.MountTypeS3: adapterFunc(func(string, int, models.MountSpec, string, string) (adapters.Plan, error) {
			close(built)
			return adapters.Plan{Argv: []string{"true"}, IsKernelMount: true}, nil
		}),
	}

	swept := make(chan struct{})
	go func() {
		m.Sweep(map[string]struct{}{})
		close(swept)
	}()
	<-inCleanup

	done := mountAsync(m, id)
	select {
	case <-built:
		t.Fatal("MountAll ran while the sweep still owned the directory")
	case <-done:
		t.Fatal("MountAll returned while the sweep still owned the directory")
	case <-time.After(200 * time.Millisecond):
	}

	close(releaseSweep)
	<-swept
	r := <-done
	if r.err != nil {
		t.Fatalf("MountAll after the sweep: %v", r.err)
	}
	if _, err := os.Stat(leftover); err != nil {
		t.Fatalf("fresh mount directory missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(leftover, "stale")); !os.IsNotExist(err) {
		t.Fatalf("leftover file survived; the mount reused the orphan: %v", err)
	}
	if len(m.HostBindsFor(id)) != 1 {
		t.Fatal("the mount is not tracked after MountAll returned")
	}
}

// On Linux the sweep still kills an orphan's mount tool through /proc.
func TestSweepKillsOrphanMountTool(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the sweep finds mount tools through /proc")
	}
	m := newTestManager(t, nil)
	hostPath := filepath.Join(m.rootDir, "sb-orphan-tool", "0")
	if err := os.MkdirAll(hostPath, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("sh", "-c", "sleep 30; :", "mount-tool", hostPath)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()
	t.Cleanup(func() { _ = killMount(cmd) })

	m.Sweep(map[string]struct{}{})
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("orphan mount tool still running after the sweep")
	}
	if _, err := os.Stat(filepath.Dir(hostPath)); !os.IsNotExist(err) {
		t.Fatalf("orphan dir not removed: %v", err)
	}
}
