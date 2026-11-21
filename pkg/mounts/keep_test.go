package mounts

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

// refuseStarts fails the test if any mount tool is started.
func refuseStarts(t *testing.T) {
	t.Helper()
	prev := startCmd
	startCmd = func(cmd *exec.Cmd) error {
		t.Errorf("started %v: KeepLive must start nothing", cmd.Args)
		return errors.New("no starts here")
	}
	t.Cleanup(func() { startCmd = prev })
}

// recordUnmounts stands in for umount.
func recordUnmounts(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var got []string
	prevU, prevL := runUmount, runLazyUmount
	runUmount = func(p string) error { mu.Lock(); got = append(got, p); mu.Unlock(); return nil }
	runLazyUmount = func(string) error { return nil }
	t.Cleanup(func() { runUmount, runLazyUmount = prevU, prevL })
	return func() []string { mu.Lock(); defer mu.Unlock(); return slices.Clone(got) }
}

// KeepLive is how a restart treats a running sandbox whose stored mounts
// the allow lists refuse but which may stay while they run: what still
// serves is taken over as it is, nothing is mounted or started, and what
// does not serve stays unmounted. Each case is a mount set a previous
// sandboxd left.
func TestKeepLiveTakesOverWhatRunsAndStartsNothing(t *testing.T) {
	nfs := models.MountSpec{Type: models.MountTypeNFS, Source: "h:/e", Target: "/nfs"}
	s3 := models.MountSpec{Type: models.MountTypeS3, Source: "s3://b", Target: "/data"}
	kernel := map[models.MountType]adapters.Adapter{models.MountTypeNFS: fakeAdapter{}, models.MountTypeS3: liveFUSEAdapter{}}

	cases := []struct {
		name      string
		specs     []models.MountSpec
		noDir     bool
		probe     func(path string) mountProbe
		remountOK bool
		wantKept  []int
		wantGone  []int
		wantUmnt  []int // indexes cleared by unmounting
	}{
		{name: "a live kernel mount is kept", specs: []models.MountSpec{nfs},
			probe: func(string) mountProbe { return mountLive }, remountOK: true, wantKept: []int{0}},
		{name: "nothing serves: nothing is mounted", specs: []models.MountSpec{nfs, s3},
			probe: func(string) mountProbe { return notMounted }, remountOK: true, wantGone: []int{0, 1}},
		{name: "a dead mount is cleared, not mounted again", specs: []models.MountSpec{nfs},
			probe: func(string) mountProbe { return mountBroken }, remountOK: true, wantGone: []int{0}, wantUmnt: []int{0}},
		{name: "a kernel mount that will not take nosuid,nodev is cleared", specs: []models.MountSpec{nfs},
			probe: func(string) mountProbe { return mountLive }, remountOK: false, wantGone: []int{0}, wantUmnt: []int{0}},
		{name: "a FUSE mount whose helper is gone is cleared", specs: []models.MountSpec{s3},
			probe: func(string) mountProbe { return mountLive }, remountOK: true, wantGone: []int{0}, wantUmnt: []int{0}},
		{name: "no folder: nothing was left", specs: []models.MountSpec{nfs}, noDir: true,
			probe: func(string) mountProbe { t.Error("probed a sandbox with no folder"); return notMounted }, wantGone: []int{0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withProcRoot(t, t.TempDir()) // no helper processes
			withProbeMount(t, tc.probe)
			prevRemount := remountNosuidNodev
			remountNosuidNodev = func(string) error {
				if tc.remountOK {
					return nil
				}
				return errors.New("mount: permission denied")
			}
			t.Cleanup(func() { remountNosuidNodev = prevRemount })
			refuseStarts(t)
			unmounted := recordUnmounts(t)

			m := newTestManager(t, kernel)
			const id = "sb-keep"
			if !tc.noDir {
				for i := range tc.specs {
					if err := os.MkdirAll(m.hostPath(id, i), 0o700); err != nil {
						t.Fatal(err)
					}
				}
			}
			report, err := m.KeepLive(t.Context(), id, tc.specs)
			if err != nil {
				t.Fatalf("KeepLive: %v", err)
			}
			if report.Already || !slices.Equal(report.Kept, tc.wantKept) || !slices.Equal(report.Gone, tc.wantGone) {
				t.Fatalf("report = %+v, want kept %v gone %v", report, tc.wantKept, tc.wantGone)
			}
			var wantUnmounted []string
			for _, i := range tc.wantUmnt {
				wantUnmounted = append(wantUnmounted, m.hostPath(id, i))
			}
			if got := unmounted(); !slices.Equal(got, wantUnmounted) {
				t.Fatalf("unmounted %v, want %v", got, wantUnmounted)
			}
			binds := m.HostBindsFor(id)
			if len(binds) != len(tc.wantKept) {
				t.Fatalf("binds = %+v, want one per kept mount %v", binds, tc.wantKept)
			}
			for j, i := range tc.wantKept {
				if binds[j].HostPath != m.hostPath(id, i) || binds[j].ContainerPath != tc.specs[i].Target {
					t.Fatalf("bind %d = %+v, want mount %d", j, binds[j], i)
				}
			}

			// Owned like any mount set: Sweep leaves it, a later pass does
			// nothing, and Discard tears it down.
			if !tc.noDir {
				m.Sweep(map[string]struct{}{})
				if _, err := os.Stat(m.hostPath(id, 0)); err != nil {
					t.Fatalf("Sweep removed a kept set: %v", err)
				}
			}
			again, err := m.KeepLive(t.Context(), id, tc.specs)
			if err != nil || !again.Already || again.Kept != nil || again.Gone != nil {
				t.Fatalf("second KeepLive = %+v, %v; want Already and nothing done", again, err)
			}
			if !m.Discard(id) {
				t.Fatal("Discard found nothing to tear down in a kept set")
			}
			if _, tracked := m.state[id]; tracked {
				t.Fatal("still tracked after Discard")
			}
		})
	}
}

// A kept helper that exits is not started again: a restart would run the
// refused spec once more. Its mount is unmounted and the set stays tracked,
// so stop or Discard still clears it. A helper kept and still running is
// stopped by UnmountAll like any adopted one.
func TestKeepLiveNeverRestartsAKeptHelper(t *testing.T) {
	proc := t.TempDir()
	withProcRoot(t, proc)
	withProbeMount(t, func(string) mountProbe { return mountLive })
	refuseStarts(t)
	unmounted := recordUnmounts(t)
	recordGroupKills(t)
	spec := []models.MountSpec{{Type: models.MountTypeS3, Source: "s3://b", Target: "/data"}}

	keep := func(t *testing.T, id string, pid int) (*Manager, *fakeLive) {
		t.Helper()
		m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeS3: liveFUSEAdapter{}})
		hostPath := m.hostPath(id, 0)
		if err := os.MkdirAll(hostPath, 0o700); err != nil {
			t.Fatal(err)
		}
		plan, _ := liveFUSEAdapter{}.Build(id, 0, spec[0], hostPath, m.credDir)
		fakeProc(t, proc, pid, plan.Argv...)
		live := newFakeLive(pid, syscall.SIGTERM)
		prevOpen := openHelperProcess
		openHelperProcess = func(gotPID int, argv []string) (liveProcess, error) {
			if gotPID != pid || !slices.Equal(argv, plan.Argv) {
				return nil, errProcessGone
			}
			return live, nil
		}
		t.Cleanup(func() { openHelperProcess = prevOpen })
		report, err := m.KeepLive(t.Context(), id, spec)
		if err != nil || !slices.Equal(report.Kept, []int{0}) {
			t.Fatalf("KeepLive = %+v, %v; want mount 0 kept", report, err)
		}
		return m, live
	}

	t.Run("exits", func(t *testing.T) {
		m, live := keep(t, "sb-kept-exit", 5151)
		hostPath := m.hostPath("sb-kept-exit", 0)
		close(live.done)
		deadline := time.Now().Add(10 * time.Second)
		for {
			m.mu.Lock()
			st := m.state["sb-kept-exit"][0]
			disabled, restarts, cmd := st.disabled, st.restarts, st.cmd
			m.mu.Unlock()
			if disabled {
				if restarts != 0 || cmd != nil {
					t.Fatalf("restarts = %d cmd = %v: a kept helper was started again", restarts, cmd)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("the kept helper's exit was never handled")
			}
			time.Sleep(5 * time.Millisecond)
		}
		if got := unmounted(); !slices.Contains(got, hostPath) {
			t.Fatalf("unmounted %v, want the kept mount's path %s", got, hostPath)
		}
		if binds := m.HostBindsFor("sb-kept-exit"); len(binds) != 1 {
			t.Fatalf("binds = %v; the set must stay tracked for stop to clear", binds)
		}
	})

	t.Run("stopped by UnmountAll", func(t *testing.T) {
		m, live := keep(t, "sb-kept-stop", 5252)
		if err := m.UnmountAll("sb-kept-stop"); err != nil {
			t.Fatalf("UnmountAll: %v", err)
		}
		live.mu.Lock()
		defer live.mu.Unlock()
		if !slices.Equal(live.signals, []syscall.Signal{syscall.SIGTERM}) {
			t.Fatalf("signals = %v, want SIGTERM", live.signals)
		}
	})
}

// KeepLive's refusals: a bad id, a mount set in flight, a cancelled wait
// for a sweep; and nothing to do for no manager or no mounts.
func TestKeepLiveRefusals(t *testing.T) {
	spec := []models.MountSpec{{Type: models.MountTypeNFS, Target: "/n"}}
	var none *Manager
	if r, err := none.KeepLive(t.Context(), "sb-x", spec); err != nil || r.Kept != nil || r.Gone != nil || r.Already {
		t.Fatalf("nil manager = %+v, %v", r, err)
	}
	m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeNFS: fakeAdapter{}})
	if r, err := m.KeepLive(t.Context(), "sb-x", nil); err != nil || r.Kept != nil || r.Gone != nil {
		t.Fatalf("no mounts = %+v, %v", r, err)
	}
	if _, err := m.KeepLive(t.Context(), "../x", spec); err == nil {
		t.Fatal("a '..' id was accepted")
	}

	release, err := m.beginMount(t.Context(), "sb-busy")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.KeepLive(t.Context(), "sb-busy", spec); !errors.Is(err, ErrMountsEstablished) {
		t.Fatalf("KeepLive during a MountAll = %v, want ErrMountsEstablished", err)
	}
	release()

	done, _ := m.claimOrphan("sb-swept")
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := m.KeepLive(cancelled, "sb-swept", spec); err == nil {
		t.Fatal("KeepLive did not give up waiting on a sweep with a cancelled context")
	}
	m.releaseOrphan("sb-swept", done)
	if _, err := os.Stat(filepath.Join(m.rootDir, "sb-swept")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("KeepLive made a folder: %v", err)
	}
}
