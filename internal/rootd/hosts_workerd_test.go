package rootd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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
	_, err := w.prepare("g1", true, nil)
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
	if _, err := w.prepare("g1", false, nil); err == nil && os.Geteuid() != 0 {
		t.Fatal("a jail was made with no kernel to make it")
	}
	if _, err := os.Stat(filepath.Join(left, "run", "config.capnp")); !os.IsNotExist(err) {
		t.Fatal("what the last workerd left was kept")
	}
	if builds != 1 || checks != 1 {
		t.Fatalf("base built %d times, checked %d", builds, checks)
	}
	_, _ = w.prepare("g2", false, nil)
	if builds != 1 {
		t.Fatal("the base was built again")
	}
	// A base that is not the helper's alone, or does not build, stops it.
	w2 := newWorkerdHosts(cfg.Workerd, cfg.LogPath)
	w2.checkBase = func(string) error { return errors.New("others can write it") }
	if _, err := w2.prepare("g1", false, nil); err == nil {
		t.Fatal("a base others can write was used")
	}
	w2.checkBase = func(string) error { return nil }
	w2.prepareBase = func() error { return errors.New("ldd: not found") }
	if _, err := w2.prepare("g1", false, nil); err == nil {
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

// TestWorkerdJailLimit: the helper keeps at most maxJails V8 jails,
// counting those on disk (running groups', the warm pool's, ones a stopped
// group left) and those being made, but not the one a group makes again
// in its own place. Past it a prepare is refused ResourceExhausted, with
// no refusal reason (a limit, not a broken request), and changes nothing.
func TestWorkerdJailLimit(t *testing.T) {
	cfg := testHostsConfig(t)
	c := *cfg.Workerd
	c.MaxJails = 2
	w := newWorkerdHosts(&c, cfg.LogPath)
	var disk []string
	w.groups = func() ([]string, error) { return slices.Clone(disk), nil }
	refused := func(err error) bool {
		var fe *fileError
		return errors.As(err, &fe) && fe.code == codes.ResourceExhausted && fe.reason == "" &&
			strings.Contains(fe.msg, "SB_ROOTD_ISOLATE_MAX_JAILS=2")
	}

	doneA, err := w.reserveJail("a")
	if err != nil {
		t.Fatal(err)
	}
	doneB, err := w.reserveJail("b") // a is being made: one other
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.reserveJail("c"); !refused(err) {
		t.Fatalf("a third jail while two are made: %v, want the limit", err)
	}
	// a's jail is on disk now; b's make failed and left none.
	disk = []string{"a"}
	doneA()
	doneB()
	if _, err := w.reserveJail("c"); err != nil {
		t.Fatalf("one jail of two: %v", err)
	}
	w.making = map[string]bool{}

	for _, tc := range []struct {
		name string
		disk []string
		id   string
		ok   bool
	}{
		{"under the limit", []string{"a"}, "b", true},
		{"at the limit", []string{"a", "b"}, "c", false},
		{"a group made again in its own place", []string{"a", "b"}, "a", true},
		{"the warm pool's and a stopped group's jails count", []string{"warm-1-0", "left"}, "t1", false},
	} {
		disk = tc.disk
		done, err := w.reserveJail(tc.id)
		if tc.ok != (err == nil) || (!tc.ok && !refused(err)) {
			t.Errorf("%s: %v, want ok %v", tc.name, err, tc.ok)
		}
		if done != nil {
			done()
		}
	}
	w.groups = func() ([]string, error) { return nil, errors.New("permission denied") }
	if _, err := w.reserveJail("a"); err == nil || refused(err) {
		t.Fatalf("a jail folder that cannot be read: %v, want its own error", err)
	}

	// Through prepare: a refused group's leftovers stay as they were.
	w.prepareBase, w.checkBase = func() error { return nil }, func(string) error { return nil }
	disk = []string{"a", "b"}
	w.groups = func() ([]string, error) { return slices.Clone(disk), nil }
	left := filepath.Join(c.Jail.ChrootBase, "c")
	if err := os.MkdirAll(left, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := w.prepare("c", false, nil); !refused(err) {
		t.Fatalf("prepare past the limit: %v", err)
	}
	if _, err := os.Stat(left); err != nil {
		t.Fatalf("a refused prepare tore down group c: %v", err)
	}
}

// TestWorkerdJailLimitOverTheSocket: the agent sees the limit as
// ResourceExhausted with no refusal detail, so its client takes it for a
// busy helper (503, retry), not a refusal it records.
func TestWorkerdJailLimitOverTheSocket(t *testing.T) {
	kernel := newFakeHostKernel()
	r := newRig(t, func(c *Config, o *Options) {
		c.Hosts = testHostsConfig(t)
		c.Hosts.Workerd.MaxJails = 1
		w := newWorkerdHosts(c.Hosts.Workerd, c.Hosts.LogPath)
		w.prepareBase, w.checkBase = func() error { return nil }, func(string) error { return nil }
		w.groups = func() ([]string, error) { return []string{"tenant-a"}, nil }
		o.HostKernel = kernel
		o.hostLaunchers = map[rootpolicy.HostKind]hostLauncher{rootpolicy.HostWorkerd: w}
	})
	_, err := hostClient(r).PrepareHost(callCtx(t), &rootdpb.PrepareHostRequest{Kind: workerd, Id: "tenant-b"})
	if status.Code(err) != codes.ResourceExhausted || !strings.Contains(err.Error(), "SB_ROOTD_ISOLATE_MAX_JAILS=1") {
		t.Fatalf("PrepareHost past the limit = %v, want ResourceExhausted naming the setting", err)
	}
	if _, ok := rootdpb.RefusalReason(err); ok || len(r.refused()) != 0 {
		t.Fatalf("the limit was answered as a refusal: %v %v", err, r.refused())
	}
}
