package isolate

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestHostStartFailsClosedWhenJailRequiredUnrealizable is the security
// regression for the false-confinement bug: when a jail is REQUIRED but this
// platform cannot realize it, Start must refuse to spawn workerd rather than run
// it unconfined. On non-Linux hosts applyJail is always unavailable, so a
// required jail always fails closed; on Linux, a spec with a root uid/gid
// (uid 0) is rejected by applyJail, which also proves the gate fires.
func TestHostStartFailsClosedWhenJailRequiredUnrealizable(t *testing.T) {
	runDir, err := os.MkdirTemp("/tmp", "isojail")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runDir) })

	// A fake workerd path that exists so Start gets past NewHost validation and
	// reaches the jail gate before exec.
	fakeWorkerd := filepath.Join(runDir, "workerd")
	if err := os.WriteFile(fakeWorkerd, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	jail := JailConfig{Require: true}
	if runtime.GOOS == "linux" {
		// On Linux applyJail is available, so force the gate via an invalid
		// (root) credential — a jailed-but-root process defeats the jail.
		jail.UID, jail.GID = 0, 0
	}

	h, err := NewHost(HostConfig{
		WorkerdPath: fakeWorkerd,
		GroupKey:    "g1",
		RunDir:      filepath.Join(runDir, "g1"),
		Jail:        jail,
	})
	if err != nil {
		t.Fatal(err)
	}
	err = h.Start(context.Background())
	if err == nil {
		_ = h.Stop()
		t.Fatal("Start succeeded with a required-but-unrealizable jail; want fail-closed error")
	}
	if !strings.Contains(err.Error(), "jail") {
		t.Fatalf("Start error = %v, want a jail fail-closed error", err)
	}
}
