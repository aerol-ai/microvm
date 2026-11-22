package rootd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// TestWorkerdHosts drives the V8 group hosts' own part with the jail's
// kernel work left out: the base built once, a running group's jail kept
// (and refused when it is not whole), a stopped one made again, no command
// without a whole jail, and every group's pids bounded.
func TestWorkerdHosts(t *testing.T) {
	cfg := testHostsConfig(t)
	w := newWorkerdHosts(cfg.Workerd, cfg.LogPath)
	builds, checks := 0, 0
	w.prepareBase = func() error { builds++; return nil }
	w.checkBase = func(string) error { checks++; return nil }

	// A running group whose jail is not whole is refused, not torn down.
	_, err := w.prepare("g1", true)
	var fe *fileError
	if !errors.As(err, &fe) || fe.code != codes.FailedPrecondition {
		t.Fatalf("prepare of a running group with no jail = %v", err)
	}
	// A stopped group's leftovers go before it is made again; the make
	// itself needs the kernel (rootjail_kernel_linux_test.go).
	left := filepath.Join(cfg.Workerd.Jail.ChrootBase, "g1")
	if err := os.MkdirAll(filepath.Join(left, "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(left, "run", "config.capnp"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := w.prepare("g1", false); err == nil && os.Geteuid() != 0 {
		t.Fatal("a jail was made with no kernel to make it")
	}
	if _, err := os.Stat(filepath.Join(left, "run", "config.capnp")); !os.IsNotExist(err) {
		t.Fatal("what the last workerd left was kept")
	}
	if builds != 1 || checks != 1 {
		t.Fatalf("base built %d times, checked %d", builds, checks)
	}
	_, _ = w.prepare("g2", false)
	if builds != 1 {
		t.Fatal("the base was built again")
	}
	// A base that is not the helper's alone, or does not build, stops it.
	w2 := newWorkerdHosts(cfg.Workerd, cfg.LogPath)
	w2.checkBase = func(string) error { return errors.New("others can write it") }
	if _, err := w2.prepare("g1", false); err == nil {
		t.Fatal("a base others can write was used")
	}
	w2.checkBase = func(string) error { return nil }
	w2.prepareBase = func() error { return errors.New("ldd: not found") }
	if _, err := w2.prepare("g1", false); err == nil {
		t.Fatal("a base that did not build was used")
	}
	// No command for a group with no whole jail.
	if _, _, err := w.command(context.Background(), "g3", &rootdpb.SpawnHostRequest{}); !errors.As(err, &fe) || fe.code != codes.FailedPrecondition {
		t.Fatalf("command of an unprepared group = %v", err)
	}
	for _, tc := range []struct{ in, want uint32 }{{0, 512}, {100, 100}, {512, 512}, {10000, 512}} {
		if l, ok := w.limits(rootpolicy.HostLimits{Pids: tc.in}); !ok || l.Pids != tc.want {
			t.Errorf("pids %d -> %d (%v), want %d", tc.in, l.Pids, ok, tc.want)
		}
	}
	if w.socket("g1") != "" || w.started(context.Background(), nil) != nil {
		t.Fatal("a V8 group has a socket or a ready signal")
	}
	if err := os.MkdirAll(filepath.Join(cfg.Workerd.Jail.ChrootBase, "g4"), 0o755); err != nil {
		t.Fatal(err)
	}
	if ids, err := w.present(); err != nil || !slices.Contains(ids, "g4") {
		t.Fatalf("present = %v, %v", ids, err)
	}
	if err := w.teardown("g4"); err != nil {
		t.Fatal(err)
	}
	if ids, _ := w.present(); slices.Contains(ids, "g4") {
		t.Fatal("teardown left the jail")
	}
	// The real base check: a folder of this test's own user passes.
	if err := newWorkerdHosts(cfg.Workerd, cfg.LogPath).checkBase(shortDir(t)); err != nil {
		t.Fatal(err)
	}
}
