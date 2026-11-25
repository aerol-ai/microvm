package supervisor

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/rootswap"
)

// restarted is a keeper on r's folders and release keys with nothing in
// memory: the runtime container started again. Its staged folder is r's,
// which the agent wrote meanwhile.
func (r *keeperRig) restarted(t *testing.T) *keeperRig {
	t.Helper()
	r2 := newKeeperRig(t, func(k *HelperKeeper) {
		k.StageDir, k.BinDir, k.Socket, k.Keys = r.k.StageDir, r.k.BinDir, r.k.Socket, r.k.Keys
	})
	r2.rel = r.rel
	return r2
}

func manifestOf(t *testing.T, body []byte, version string) rootswap.Manifest {
	t.Helper()
	m, err := rootswap.NewManifest(bytes.NewReader(body), version, 1, runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func floorVersion(t *testing.T, bin string) string {
	t.Helper()
	f, err := rootswap.ReadFloor(bin)
	if err != nil || f == nil {
		t.Fatalf("floor: %+v, %v", f, err)
	}
	return f.Version
}

// TestHelperFloorSurvivesRestart ⭐: the rule "never a helper older than the
// one that ran" holds across a restart of the runtime container. The keeper
// that starts again has nothing in memory; it reads the floor the last one
// left in its folder of copies, so an older release the agent staged
// meanwhile, signed and whole, is refused, and the same release or a newer
// one runs.
func TestHelperFloorSurvivesRestart(t *testing.T) {
	for _, tc := range []struct {
		name, version string
		runs          bool
	}{
		{"an older release", "v1.0.0", false},
		{"an older release line", "v0.9.9", false},
		{"the same release", "v1.0.1", true},
		{"a newer release", "v1.0.2", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newKeeperRig(t, nil)
			r.rel.stage([]byte("helper v1.0.1"), "v1.0.1")
			r.run()
			r.waitStarts(1)
			eventually(t, "v1.0.1 serving", func() bool { return strings.Contains(r.logs.String(), "the root helper serves") })
			if v := floorVersion(t, r.k.BinDir); v != "v1.0.1" {
				t.Fatalf("floor %s after the first start, want v1.0.1", v)
			}
			r.stop()

			r.rel.stage([]byte("helper "+tc.version), tc.version)
			r2 := r.restarted(t)
			r2.run()
			if !tc.runs {
				eventually(t, "the refusal", func() bool { return strings.Contains(r2.logs.String(), "reason=older") })
				time.Sleep(50 * time.Millisecond) // many ticks
				if n := len(r2.starts()); n != 0 {
					t.Fatalf("%d starts of an older helper after a restart; logs:\n%s", n, r2.logs.String())
				}
				if !strings.Contains(r2.logs.String(), "level=ERROR msg=\"supervisor: refused the staged root helper\"") {
					t.Fatalf("the refusal with no helper running is not an error; logs:\n%s", r2.logs.String())
				}
				// A release not older is still taken.
				r.rel.stage([]byte("helper v1.0.3"), "v1.0.3")
				tc.version = "v1.0.3"
			}
			c := r2.waitStarts(1)[0]
			if !strings.Contains(c.bin, tc.version) {
				t.Fatalf("after the restart ran %s, want %s", c.bin, tc.version)
			}
			if v := floorVersion(t, r2.k.BinDir); v != tc.version {
				t.Fatalf("floor %s, want %s", v, tc.version)
			}
		})
	}
}

// TestHelperFloorUnreadable: a floor that is there but cannot be read runs
// no staged helper at all, said once, until root's folder is right again.
func TestHelperFloorUnreadable(t *testing.T) {
	r := newKeeperRig(t, nil)
	if err := os.MkdirAll(r.k.BinDir, 0o700); err != nil {
		t.Fatal(err)
	}
	floor := filepath.Join(r.k.BinDir, rootswap.FloorName)
	if err := os.WriteFile(floor, []byte("{half"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := []byte("helper v1")
	r.rel.stage(body, "v1.0.0")
	r.run()
	eventually(t, "the floor error", func() bool {
		return strings.Contains(r.logs.String(), "cannot read the version of the root helper that ran last")
	})
	time.Sleep(50 * time.Millisecond) // many ticks
	if n := len(r.starts()); n != 0 {
		t.Fatalf("%d starts with a floor that cannot be read", n)
	}
	if n := strings.Count(r.logs.String(), "cannot read the version of the root helper that ran last"); n != 1 {
		t.Fatalf("the error was logged %d times, want once", n)
	}
	if err := rootswap.WriteFloor(r.k.BinDir, manifestOf(t, body, "v1.0.0")); err != nil {
		t.Fatal(err)
	}
	if c := r.waitStarts(1)[0]; !strings.Contains(c.bin, "v1.0.0") {
		t.Fatalf("ran %s", c.bin)
	}
}

// TestHelperFloorWriteFails: a new helper whose version cannot be recorded
// does not run. With none running, none starts; with one running, it keeps
// serving, untouched. Both are tried again once the floor can be written.
func TestHelperFloorWriteFails(t *testing.T) {
	ctx := context.Background()
	r := newKeeperRig(t, nil)
	r.k.defaults()
	t.Cleanup(func() {
		if r.k.child != nil {
			r.k.stop(r.k.child)
		}
		r.k.closeSocket()
	})
	floor := filepath.Join(r.k.BinDir, rootswap.FloorName)
	// judge looks until the staged set is judged: a set seen for the first
	// time waits a look.
	judge := func() *rootswap.Installed {
		t.Helper()
		for range 3 {
			if inst := r.k.look(); inst != nil {
				return inst
			}
		}
		t.Fatalf("nothing to run; logs:\n%s", r.logs.String())
		return nil
	}
	r.rel.stage([]byte("helper v1"), "v1.0.0")
	v1 := judge()
	if err := os.Mkdir(floor, 0o700); err != nil { // the floor cannot be written now
		t.Fatal(err)
	}
	r.k.swap(ctx, v1)
	if n := len(r.starts()); n != 0 || r.k.cur != nil {
		t.Fatalf("%d starts, cur %v, with no floor written", n, r.k.cur)
	}
	if _, err := os.Stat(v1.Path); !os.IsNotExist(err) {
		t.Fatalf("the copy that did not run was left: %v", err)
	}
	if err := os.Remove(floor); err != nil {
		t.Fatal(err)
	}
	r.k.swap(ctx, judge())
	first := r.waitStarts(1)[0]

	r.rel.stage([]byte("helper v2"), "v1.0.1")
	v2 := judge()
	if err := os.Remove(floor); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(floor, 0o700); err != nil {
		t.Fatal(err)
	}
	r.k.swap(ctx, v2)
	if n := len(r.starts()); n != 1 || first.exited() || slices.Contains(first.got(), syscall.SIGTERM) {
		t.Fatalf("%d starts; v1 exited %v, got %v: a helper whose version was not recorded replaced it", n, first.exited(), first.got())
	}
	if !strings.Contains(r.logs.String(), "could not record the new root helper's version") {
		t.Fatalf("logs:\n%s", r.logs.String())
	}
	if err := os.Remove(floor); err != nil {
		t.Fatal(err)
	}
	r.k.swap(ctx, judge())
	if second := r.waitStarts(2)[1]; !strings.Contains(second.bin, "v1.0.1") || !first.exited() {
		t.Fatalf("second start ran %s; v1 exited %v", second.bin, first.exited())
	}
	if v := floorVersion(t, r.k.BinDir); v != "v1.0.1" {
		t.Fatalf("floor %s, want v1.0.1", v)
	}
}
