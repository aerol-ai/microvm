package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	isolateruntime "github.com/aerol-ai/microvm/internal/runtime/isolate"
	"github.com/aerol-ai/microvm/internal/service"
	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
)

func TestCoverage95IsolateBundleStoreError(t *testing.T) {
	badDir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(badDir, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := wireIsolateRuntime(context.Background(), config.Config{
		EnableIsolate:      true,
		IsolateRunDir:      badDir,
		IsolateWorkerdPath: "/nonexistent-workerd",
	}, testLogger(), nil)
	if err == nil {
		t.Fatal("want bundle store error")
	}
}

func TestCoverage95IsolateBackgroundAndPoolSpawner(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startIsolateBackground(ctx, config.Config{}, nil, nil)

	st := openTestStore(t)
	svc := service.New(config.Config{EnableIsolate: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	driver := isolateruntime.New(isolateruntime.FromDaemonConfig(config.Config{}), testLogger())
	startIsolateBackground(ctx, config.Config{IsolateBundleGCInterval: time.Millisecond}, driver, svc)

	spawner := &poolSpawner{supervisor: isolateruntime.NewHostSupervisor(isolateruntime.Config{
		WorkerdPath: "/nonexistent-workerd",
		RunDir:      t.TempDir(),
	})}
	if _, err := spawner.Spawn(context.Background()); err == nil {
		t.Fatal("Spawn with missing workerd unexpectedly succeeded")
	}
	if got := spawner.n.Load(); got != 1 {
		t.Fatalf("spawn sequence = %d, want 1", got)
	}
}

func TestCoverage95IsolateWarmPoolWiring(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Exercise the pool wiring without trying to start workerd.

	st := openTestStore(t)
	svc := service.New(config.Config{EnableIsolate: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	driver, err := wireIsolateRuntime(ctx, config.Config{
		EnableIsolate:             true,
		IsolateWorkerdPath:        "/nonexistent-workerd",
		IsolateRunDir:             t.TempDir(),
		IsolatePoolEnabled:        true,
		IsolatePoolDepthDefault:   1,
		IsolatePoolRefillInterval: time.Hour,
	}, testLogger(), svc)
	if err != nil {
		t.Fatalf("wireIsolateRuntime: %v", err)
	}
	if driver == nil {
		t.Fatal("wireIsolateRuntime returned nil driver")
	}
}

// A required jail is prepared at boot and fails boot — never the first
// create — when this host cannot realize it.
func TestIsolateJailBootstrapFailsClosedAtBoot(t *testing.T) {
	if pkgisolate.JailRealizable() && os.Geteuid() == 0 {
		t.Skip("root on linux realizes the jail; covered by the real-host scenario")
	}
	orig := isolateShimPath
	t.Cleanup(func() { isolateShimPath = orig })
	isolateShimPath = func() (string, error) { return "/usr/local/bin/sandboxd", nil }
	st := openTestStore(t)
	svc := service.New(config.Config{EnableIsolate: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	cfg := config.Config{
		EnableIsolate: true, IsolateUseJail: true, IsolateRunDir: t.TempDir(),
		IsolateWorkerdPath: "/nonexistent-workerd", IsolateJailChrootBase: filepath.Join(t.TempDir(), "jail"),
		IsolateJailUID: 1001, IsolateJailGID: 1001, IsolateSeccompMode: "enforce",
	}
	_, err := wireIsolateRuntime(context.Background(), cfg, testLogger(), svc)
	if err == nil {
		t.Fatal("jail-on boot succeeded on a host that cannot realize the jail")
	}
	if !strings.Contains(err.Error(), "isolate jail") {
		t.Fatalf("err = %v, want a jail bootstrap error", err)
	}
	// A shim that cannot be located is also a boot failure.
	isolateShimPath = func() (string, error) { return "", errors.New("no exe") }
	if _, err := wireIsolateRuntime(context.Background(), cfg, testLogger(), svc); err == nil || !strings.Contains(err.Error(), "jail shim") {
		t.Fatalf("missing shim err = %v", err)
	}
	// Jail off: the same config boots (workerd missing only bites at create).
	cfg.IsolateUseJail = false
	if _, err := wireIsolateRuntime(context.Background(), cfg, testLogger(), svc); err != nil {
		t.Fatalf("jail-off boot: %v", err)
	}
}

type recordingSupervisor struct {
	specs []isolateruntime.JailSpec
}

func (r *recordingSupervisor) SpawnGroup(_ context.Context, spec isolateruntime.JailSpec) (isolateruntime.GroupHost, error) {
	r.specs = append(r.specs, spec)
	return nil, errors.New("not spawning in test")
}

// Warm blanks are jailed exactly like tenant groups (chroot, uid, filter,
// shim) with unlimited caps; an unjailed pool keeps its run-dir-only spec.
func TestIsolatePoolSpawnerJailsWarmBlanks(t *testing.T) {
	rec := &recordingSupervisor{}
	jailed := &poolSpawner{supervisor: rec, cfg: isolateruntime.Config{
		UseJail: true, JailChrootBase: "/srv/jail", JailUID: 1001, JailGID: 1001,
		JailCgroupRoot: "/sys/fs/cgroup/x", SeccompMode: "enforce", ShimPath: "/sandboxd",
	}}
	_, _ = jailed.Spawn(context.Background())
	if len(rec.specs) != 1 {
		t.Fatalf("spawns = %d", len(rec.specs))
	}
	spec := rec.specs[0]
	if spec.GroupKey != "warm-1" || spec.ChrootDir != "/srv/jail/warm-1" || spec.UID != 1001 || spec.CgroupRoot != "/sys/fs/cgroup/x" ||
		spec.SeccompMode != "enforce" || spec.ShimPath != "/sandboxd" || spec.CPUQuota != 0 || spec.MemoryLimitMB != 0 {
		t.Fatalf("warm blank spec = %+v", spec)
	}
	// A jail identity that cannot form a valid spec refuses to spawn blanks
	// rather than spawning them unjailed.
	bad := &poolSpawner{supervisor: rec, cfg: isolateruntime.Config{UseJail: true, JailChrootBase: "/srv/jail", JailUID: 0, JailGID: 0}}
	if _, err := bad.Spawn(context.Background()); err == nil || !strings.Contains(err.Error(), "jail spec") {
		t.Fatalf("root jail identity err = %v", err)
	}
	if len(rec.specs) != 1 {
		t.Fatal("an unjailed blank was spawned under a jail-on config")
	}
	plain := &poolSpawner{supervisor: rec, cfg: isolateruntime.Config{UseJail: false}}
	_, _ = plain.Spawn(context.Background())
	if got := rec.specs[len(rec.specs)-1]; got.GroupKey != "warm-1" || got.ChrootDir != "" {
		t.Fatalf("unjailed blank spec = %+v", got)
	}
}
