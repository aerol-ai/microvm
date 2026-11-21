package mounts

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// Discard is how the service refuses a sandbox's stored mounts on start, and
// tears down a running sandbox's after a restart when they may not run on:
// tracked mounts are torn down, and whatever a previous sandboxd left in
// the sandbox's directory is cleared, the way Sweep clears an orphan, so a
// refused helper stops serving. It reports whether there was anything.
func TestDiscard(t *testing.T) {
	t.Run("tracked mounts", func(t *testing.T) {
		m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeNFS: fakeAdapter{}})
		if _, err := m.MountAll(t.Context(), "sb-tracked", []models.MountSpec{{Type: models.MountTypeNFS, Target: "/n"}}); err != nil {
			t.Fatalf("MountAll: %v", err)
		}
		if !m.Discard("sb-tracked") {
			t.Fatal("Discard reported nothing torn down")
		}
		if binds := m.HostBindsFor("sb-tracked"); len(binds) != 0 {
			t.Fatalf("still tracked: %v", binds)
		}
		if _, err := os.Stat(filepath.Join(m.rootDir, "sb-tracked")); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("directory left: %v", err)
		}
	})

	t.Run("left by a previous sandboxd", func(t *testing.T) {
		var logs bytes.Buffer
		m := newTestManager(t, nil)
		m.logger = slog.New(slog.NewTextHandler(&logs, nil))
		left := filepath.Join(m.rootDir, "sb-left", "0")
		if err := os.MkdirAll(left, 0o700); err != nil {
			t.Fatal(err)
		}
		if !m.Discard("sb-left") {
			t.Fatal("Discard reported nothing torn down")
		}
		if _, err := os.Stat(filepath.Dir(left)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("directory left: %v", err)
		}
		if !strings.Contains(logs.String(), "discarding refused mounts") {
			t.Fatalf("not logged: %s", logs.String())
		}
		if _, swept := m.sweeping["sb-left"]; swept {
			t.Fatal("the claim was not released")
		}
	})

	t.Run("a live mount that will not unmount keeps its files", func(t *testing.T) {
		m := newTestManager(t, nil)
		hostPath := m.hostPath("sb-stuck", 0)
		if err := os.MkdirAll(hostPath, 0o700); err != nil {
			t.Fatal(err)
		}
		kept := filepath.Join(hostPath, "keep")
		if err := os.WriteFile(kept, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		fakeMountTable(t, hostPath)
		stubUmount(t, func(string) bool { return false })
		if !m.Discard("sb-stuck") {
			t.Fatal("Discard reported nothing torn down")
		}
		if _, err := os.Stat(kept); err != nil {
			t.Fatalf("Discard deleted through a live mount: %v", err)
		}
		if _, swept := m.sweeping["sb-stuck"]; swept {
			t.Fatal("the claim was not released")
		}
	})

	t.Run("a mount in flight owns the directory", func(t *testing.T) {
		m := newTestManager(t, nil)
		dir := filepath.Join(m.rootDir, "sb-busy")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		release, err := m.beginMount(t.Context(), "sb-busy")
		if err != nil {
			t.Fatal(err)
		}
		defer release()
		if m.Discard("sb-busy") {
			t.Fatal("Discard reported a teardown it left to the MountAll")
		}
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("removed a directory a MountAll owns: %v", err)
		}
	})

	t.Run("nothing there, a bad id, no manager", func(t *testing.T) {
		m := newTestManager(t, nil)
		if m.Discard("sb-none") {
			t.Fatal("Discard reported a teardown with nothing there")
		}
		outside := filepath.Join(filepath.Dir(m.rootDir), "keep")
		if err := os.MkdirAll(outside, 0o700); err != nil {
			t.Fatal(err)
		}
		if m.Discard("../keep") {
			t.Fatal("Discard reported a teardown for a '..' id")
		}
		if _, err := os.Stat(outside); err != nil {
			t.Fatalf("a '..' id reached outside the root: %v", err)
		}
		var none *Manager
		if none.Discard("sb-x") {
			t.Fatal("a nil manager reported a teardown")
		}
	})
}

// A kernel mount a previous sandboxd left is adopted only once nosuid,nodev
// are set on it: one made before the NFS adapter forced them may lack them.
// If they cannot be set it is not adopted, and the caller clears it and
// mounts afresh with them.
func TestAdoptKernelMountRemountsNosuidNodev(t *testing.T) {
	var remounted []string
	remountErr := error(nil)
	prev := remountNosuidNodev
	remountNosuidNodev = func(path string) error { remounted = append(remounted, path); return remountErr }
	t.Cleanup(func() { remountNosuidNodev = prev })
	withProbeMount(t, func(string) mountProbe { return mountLive })

	var logs bytes.Buffer
	m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeNFS: fakeAdapter{}})
	m.logger = slog.New(slog.NewTextHandler(&logs, nil))
	spec := models.MountSpec{Type: models.MountTypeNFS, Source: "h:/e", Target: "/nfs"}
	hostPath := m.hostPath("sb-k", 0)

	if state, _ := m.adoptOne(context.Background(), "sb-k", 0, spec, nil); state == nil {
		t.Fatal("a live kernel mount was not adopted")
	}
	if len(remounted) != 1 || remounted[0] != hostPath {
		t.Fatalf("remounted %v, want %s", remounted, hostPath)
	}

	remountErr = errors.New("mount: permission denied")
	if state, _ := m.adoptOne(context.Background(), "sb-k", 0, spec, nil); state != nil {
		t.Fatal("adopted a kernel mount whose nosuid,nodev could not be set")
	}
	if !strings.Contains(logs.String(), "could not set nosuid,nodev") {
		t.Fatalf("not logged: %s", logs.String())
	}
}
