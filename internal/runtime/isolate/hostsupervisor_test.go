package isolate

import (
	"context"
	"os"
	"path/filepath"
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
