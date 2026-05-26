package firecracker

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestJailerExpectsBase covers the precondition checker the layout helper
// calls. The point isn't the strings — it's that newVMM rejects a
// half-configured jailer setup at construction time, not at spawn time
// where the error is harder for an operator to read.
func TestJailerExpectsBase(t *testing.T) {
	t.Run("disabled returns error", func(t *testing.T) {
		_, err := Config{}.jailerExpectsBase()
		if err == nil {
			t.Fatal("expected error when UseJailer is false")
		}
	})
	t.Run("missing jailer binary", func(t *testing.T) {
		_, err := Config{UseJailer: true, JailerChrootBase: "/x"}.jailerExpectsBase()
		if err == nil {
			t.Fatal("expected error for missing JailerBinary")
		}
	})
	t.Run("missing chroot base", func(t *testing.T) {
		_, err := Config{UseJailer: true, JailerBinary: "/usr/local/bin/jailer"}.jailerExpectsBase()
		if err == nil {
			t.Fatal("expected error for missing JailerChrootBase")
		}
	})
	t.Run("ok", func(t *testing.T) {
		base, err := Config{
			UseJailer:        true,
			JailerBinary:     "/usr/local/bin/jailer",
			JailerChrootBase: "/srv/jailer",
		}.jailerExpectsBase()
		if err != nil {
			t.Fatalf("expected nil err, got %v", err)
		}
		if base != "/srv/jailer" {
			t.Errorf("base = %q, want /srv/jailer", base)
		}
	})
}

// TestJailedPaths confirms the host/chroot path math matches the layout
// described in jailer.go's header (which is verbatim from the upstream
// jailer docs). If the math drifts, the daemon writes the kernel into a
// directory the jailed firecracker can't see, and the boot fails in a
// way that's hard to diagnose. Lock the math down here.
func TestJailedPaths(t *testing.T) {
	const base = "/srv/jailer"
	const id = "sb-abc"

	gotRoot := jailedRootDir(base, id)
	wantRoot := "/srv/jailer/firecracker/sb-abc/root"
	if gotRoot != wantRoot {
		t.Errorf("jailedRootDir = %q, want %q", gotRoot, wantRoot)
	}

	gotSock := jailedAPISocketHostPath(base, id)
	wantSock := "/srv/jailer/firecracker/sb-abc/root/api.socket"
	if gotSock != wantSock {
		t.Errorf("jailedAPISocketHostPath = %q, want %q", gotSock, wantSock)
	}
}

// TestApplyJailerLayout_Disabled exercises the no-op branch — when
// UseJailer is false the constructor's paths should keep the direct-mode
// values regardless of any stray jailer config.
func TestApplyJailerLayout_Disabled(t *testing.T) {
	dir := t.TempDir()
	v, err := newVMM(Config{
		FirecrackerBinary: "/fc",
		RunDir:            dir,
		// Stray-but-harmless jailer fields:
		JailerChrootBase: "/srv/jailer",
		JailerBinary:     "/usr/local/bin/jailer",
	}, "sb-direct", nil)
	if err != nil {
		t.Fatalf("newVMM: %v", err)
	}
	wantRunDir := filepath.Join(dir, "sb-direct")
	if v.runDir != wantRunDir {
		t.Errorf("runDir = %q, want %q", v.runDir, wantRunDir)
	}
	wantSock := filepath.Join(wantRunDir, "api.sock")
	if v.APISocket() != wantSock {
		t.Errorf("APISocket = %q, want %q", v.APISocket(), wantSock)
	}
}

// TestApplyJailerLayout_Enabled flips UseJailer and confirms the
// constructor moves runDir + apiSocket into the chroot tree under
// JailerChrootBase. After this, Cleanup's safety check uses JailerChrootBase
// as the prefix — exercised separately in TestCleanupRespectsJailerRoot.
func TestApplyJailerLayout_Enabled(t *testing.T) {
	cfg := Config{
		FirecrackerBinary: "/usr/local/bin/firecracker",
		RunDir:            "/run/sandboxd/firecracker", // ignored in jailer mode
		UseJailer:         true,
		JailerBinary:      "/usr/local/bin/jailer",
		JailerChrootBase:  "/srv/jailer",
		JailerUID:         1000,
		JailerGID:         1000,
	}
	v, err := newVMM(cfg, "sb-jailed", nil)
	if err != nil {
		t.Fatalf("newVMM: %v", err)
	}
	if v.runDir != "/srv/jailer/firecracker/sb-jailed/root" {
		t.Errorf("runDir = %q, want chroot root", v.runDir)
	}
	if v.APISocket() != "/srv/jailer/firecracker/sb-jailed/root/api.socket" {
		t.Errorf("APISocket = %q, want chroot host-visible socket path", v.APISocket())
	}
	if !strings.HasSuffix(v.logPath, "/root/firecracker.log") {
		t.Errorf("logPath = %q, want suffix /root/firecracker.log", v.logPath)
	}
}

// TestApplyJailerLayout_IncompleteConfig confirms newVMM fails when
// UseJailer is true but JailerChrootBase is missing — preferable to
// silently rooting under "/firecracker/<id>/root" and corrupting the
// host's root filesystem if RemoveAll later runs.
func TestApplyJailerLayout_IncompleteConfig(t *testing.T) {
	cfg := Config{
		FirecrackerBinary: "/fc",
		RunDir:            "/run/sb",
		UseJailer:         true,
		JailerBinary:      "/usr/local/bin/jailer",
		// JailerChrootBase intentionally empty
	}
	if _, err := newVMM(cfg, "id", nil); err == nil {
		t.Fatal("expected newVMM to reject incomplete jailer config")
	}
}

// TestJailerArgv locks down the wire shape passed to the jailer binary.
// Firecracker rejects unknown flags with an error at boot, but the
// classes of subtle bugs (wrong argument order around the double-dash,
// missing --id, swapped --uid/--gid) are what this test catches before
// the operator ever sees the boot failure. Anchor on the upstream docs:
// https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md
func TestJailerArgv(t *testing.T) {
	cfg := Config{
		FirecrackerBinary: "/opt/fc/firecracker",
		UseJailer:         true,
		JailerBinary:      "/opt/fc/jailer",
		JailerChrootBase:  "/srv/jailer",
		JailerUID:         1234,
		JailerGID:         5678,
	}
	v, err := newVMM(cfg, "sb-argv", nil)
	if err != nil {
		t.Fatalf("newVMM: %v", err)
	}
	argv := v.jailerArgv()

	// Required flag pairs jailer needs, in any order. Build a map so the
	// test doesn't get coupled to the slice order — only the
	// double-dash-separated structure matters.
	want := map[string]string{
		"--id":              "sb-argv",
		"--exec-file":       "/opt/fc/firecracker",
		"--uid":             "1234",
		"--gid":             "5678",
		"--chroot-base-dir": "/srv/jailer",
	}
	dashIdx := -1
	for i, a := range argv {
		if a == "--" {
			dashIdx = i
			break
		}
	}
	if dashIdx == -1 {
		t.Fatalf("argv missing '--' separator: %v", argv)
	}
	pre := argv[:dashIdx]
	post := argv[dashIdx+1:]

	got := map[string]string{}
	for i := 0; i+1 < len(pre); i += 2 {
		got[pre[i]] = pre[i+1]
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("argv pre-dashdash[%q] = %q, want %q", k, got[k], v)
		}
	}

	// After the dashdash: --api-sock api.socket (relative; jailer
	// resolves it inside the chroot). An absolute path here would mean
	// firecracker binds the socket OUTSIDE the chroot, which is a config
	// bug — the test pins the relative form.
	if len(post) != 2 || post[0] != "--api-sock" || post[1] != jailerAPISocketName {
		t.Errorf("argv post-dashdash = %v, want [--api-sock %s]", post, jailerAPISocketName)
	}
	if filepath.IsAbs(post[1]) {
		t.Errorf("api-sock %q must be relative (chroot-internal)", post[1])
	}
}

// TestCleanupRespectsJailerRoot confirms the Cleanup safety check accepts
// the chroot path when UseJailer is true. Without this test, the
// validateSandboxID/HasPrefix check from vmm.go could reject a legitimate
// cleanup and leak the chroot tree across restarts.
func TestCleanupRespectsJailerRoot(t *testing.T) {
	tmp := t.TempDir()
	chrootBase := filepath.Join(tmp, "srv-jailer")

	cfg := Config{
		FirecrackerBinary: "/fc",
		RunDir:            "/unused/run",
		UseJailer:         true,
		JailerBinary:      "/usr/local/bin/jailer",
		JailerChrootBase:  chrootBase,
		JailerUID:         1000,
		JailerGID:         1000,
	}
	v, err := newVMM(cfg, "sb-cleanup", nil)
	if err != nil {
		t.Fatalf("newVMM: %v", err)
	}
	// Materialize the chroot path so RemoveAll has something to do.
	if err := os.MkdirAll(v.runDir, 0o755); err != nil {
		t.Fatalf("mkdir runDir: %v", err)
	}
	if err := v.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}
	if _, err := os.Stat(v.runDir); !os.IsNotExist(err) {
		t.Fatalf("chroot path still exists after Cleanup: %v", err)
	}
}
