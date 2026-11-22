package isolate

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkgisolate "github.com/aerol-ai/microvm/pkg/isolate"
)

func TestHostAdapterSetEgressPolicy(t *testing.T) {
	runDir := t.TempDir()
	workerd := filepath.Join(runDir, "workerd")
	if err := os.WriteFile(workerd, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	host, err := pkgisolate.NewHost(pkgisolate.HostConfig{
		WorkerdPath: workerd,
		GroupKey:    "acme",
		RunDir:      filepath.Join(runDir, "group"),
	})
	if err != nil {
		t.Fatal(err)
	}
	adapter := &hostAdapter{Host: host}
	adapter.SetEgressPolicy("sb-1", EgressPolicy{
		BlockAll: false,
		Allow:    []string{"api.example.com"},
		Deny:     []string{"evil.com"},
	})
}

func TestHostSupervisorSpawnStartFailure(t *testing.T) {
	runDir := t.TempDir()
	// Exists but exits immediately — NewHost ok, Start fails waiting for control socket.
	// Bound the wait: waitReady only returns on ctx cancel or readiness.
	workerd := filepath.Join(runDir, "workerd")
	if err := os.WriteFile(workerd, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sup := NewHostSupervisor(Config{WorkerdPath: workerd, RunDir: runDir})
	spec, err := BuildJailSpec(Config{JailChrootBase: "/srv/jail", JailUID: 1000, JailGID: 1000}, "acme", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if _, err := sup.SpawnGroup(ctx, spec); err == nil {
		t.Fatal("SpawnGroup should fail when workerd exits immediately")
	}
}

func TestHostSupervisorSpawnNewHostFailure(t *testing.T) {
	// Empty RunDir makes NewHost fail before Start — covers SpawnGroup's
	// construction error branch without waiting on readiness.
	sup := NewHostSupervisor(Config{WorkerdPath: "/nonexistent-workerd", RunDir: ""})
	spec, err := BuildJailSpec(Config{JailChrootBase: "/srv/jail", JailUID: 1000, JailGID: 1000}, "acme", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sup.SpawnGroup(context.Background(), spec); err == nil {
		t.Fatal("SpawnGroup should fail with empty RunDir")
	}
}

// A jailed group's run dir must sit inside its chroot (pkg/isolate maps the
// paths for workerd); a spec without a chroot cannot be jailed at all.
func TestHostSupervisorJailedRunDirLivesInsideChroot(t *testing.T) {
	sup := NewHostSupervisor(Config{WorkerdPath: "/nonexistent-workerd", RunDir: t.TempDir(), UseJail: true})
	if _, err := sup.SpawnGroup(context.Background(), JailSpec{GroupKey: "acme"}); err == nil || !strings.Contains(err.Error(), "no chroot dir") {
		t.Fatalf("jailed spawn without chroot err = %v", err)
	}
	spec, err := BuildJailSpec(Config{JailChrootBase: "/srv/jail", JailUID: 1000, JailGID: 1000, UseJail: true, SeccompMode: "enforce", ShimPath: "/sandboxd"}, "acme", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	// Realization fails on this host (no root / not linux) — but only after
	// NewHost accepted the chroot-relative run dir, which is what we assert:
	// the error is the jail's fail-closed refusal, not a run-dir mismatch.
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	_, err = sup.SpawnGroup(ctx, spec)
	if err == nil {
		t.Fatal("jailed spawn succeeded without a realizable jail")
	}
	if strings.Contains(err.Error(), "jailed run dir") {
		t.Fatalf("run dir contract not applied by the supervisor: %v", err)
	}
}

// recordingLauncher is the root helper (privilege mode split) as the
// supervisor hands it to each host; its Prepare fails so nothing starts.
type recordingLauncher struct {
	pkgisolate.JailLauncher
	prepared []string
	groups   []string
	stopped  []string
}

func (l *recordingLauncher) Prepare(_ context.Context, group string) (string, error) {
	l.prepared = append(l.prepared, group)
	return "", context.Canceled
}

func (l *recordingLauncher) Groups(context.Context) ([]string, error) { return l.groups, nil }

func (l *recordingLauncher) Stop(_ context.Context, group string) error {
	l.stopped = append(l.stopped, group)
	return nil
}

// TestHostSupervisorHandsGroupsToTheLauncher: in split mode every group
// goes to the launcher, which also gets the group's pids bound; and boot
// sweeps what it holds through it, never the cgroup or chroot folders.
func TestHostSupervisorHandsGroupsToTheLauncher(t *testing.T) {
	l := &recordingLauncher{groups: []string{"left"}}
	cfg := Config{WorkerdPath: "/usr/local/bin/workerd", RunDir: t.TempDir(), UseJail: true, JailChrootBase: "/srv/isolate-jail",
		JailUID: 1000, JailGID: 1000, JailPidsMax: 77, JailCgroupRoot: "/nonexistent/cgroup", Launcher: l}
	sup := newWorkerdSupervisor(cfg, nil)
	if sup.launchedPids(77) != 77 {
		t.Fatal("a launched group lost its pids bound")
	}
	spec, err := BuildJailSpec(cfg, "acme", 0.5, 64)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sup.SpawnGroup(context.Background(), spec); err == nil || !strings.Contains(err.Error(), "prepare group acme") {
		t.Fatalf("SpawnGroup = %v", err)
	}
	if len(l.prepared) != 1 || l.prepared[0] != "acme" {
		t.Fatalf("launcher prepared %v", l.prepared)
	}
	if adopted := sup.AdoptGroups(context.Background()); len(adopted) != 0 {
		t.Fatalf("adopted %v", adopted)
	}
	if len(l.stopped) != 1 || l.stopped[0] != "left" {
		t.Fatalf("boot sweep stopped %v", l.stopped)
	}
	// Single mode passes no pids at spawn, as before.
	if newWorkerdSupervisor(Config{}, nil).launchedPids(77) != 0 {
		t.Fatal("single mode's spawn changed")
	}
}
