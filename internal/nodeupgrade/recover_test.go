package nodeupgrade

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/release"
)

// crashAt runs an upgrade that dies at point, the way a killed upgrader or
// a power cut does: no failure path runs, and the lock goes with the
// process (runtime.Goexit runs only the deferred release).
func crashAt(t *testing.T, r *rig, req Request, point string, mid string) {
	t.Helper()
	r.u.hook = func(p string) {
		if p == point {
			runtime.Goexit()
		}
	}
	if mid != "" {
		midSwapHook = func(dst string) {
			if dst == mid {
				runtime.Goexit()
			}
		}
		t.Cleanup(func() { midSwapHook = nil })
	}
	done := make(chan struct{})
	finished := false
	go func() {
		defer close(done)
		_, _ = r.u.Run(context.Background(), req)
		finished = true
	}()
	<-done
	if finished {
		t.Fatalf("the upgrade ran to the end without reaching %q%s\n%s", point, mid, r.out)
	}
	r.u.hook = nil
	midSwapHook = nil
}

// Crash safety (§6.3 "a reboot mid-swap", plan §10): kill the upgrader
// after each file swap and at each step around it; the next boot completes
// the op when every new file is in place and otherwise puts back what was
// swapped, so the node never runs a half-swapped set.
func TestBootRecoveryAfterACrashAtEveryStep(t *testing.T) {
	cases := []struct {
		name          string
		point         string
		mid           func(r *rig) string
		wantCompleted bool
		wantSelf      bool
	}{
		{name: "mid-swap of toolboxd", mid: func(r *rig) string { return r.paths.Toolboxd }},
		{name: "toolboxd swapped, not recorded", point: "swapped-unrecorded:toolboxd"},
		{name: "after toolboxd", point: "swapped:toolboxd"},
		{name: "mid-swap of caddy", mid: func(r *rig) string { return r.paths.Caddy }},
		{name: "after caddy", point: "swapped:caddy"},
		{name: "mid-swap of sandboxd", mid: func(r *rig) string { return r.paths.Sandboxd }},
		{name: "sandboxd swapped, not recorded", point: "swapped-unrecorded:sandboxd", wantCompleted: true},
		{name: "after sandboxd", point: "swapped:sandboxd", wantCompleted: true},
		{name: "started, before health", point: "started", wantCompleted: true},
		{name: "while reverting", point: "reverting", wantSelf: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := newRelease("v0.6.11")
			next := newRelease("v0.6.12").withMeta(func(m *release.Metadata) { m.EgressGatewayProtocol = []int{2, 3} })
			r := newRig(t, old)
			r.host.active[gatewayUnit] = true
			r.host.gateway = 1
			req := r.from(next)
			if tc.point == "reverting" {
				// Reverting starts once the new binary fails its health check.
				next.sandboxd = fakeBinary("v0.6.12", true, "UNHEALTHY")
				req = r.from(next)
			}
			mid := ""
			if tc.mid != nil {
				mid = tc.mid(r)
			}
			crashAt(t, r, req, tc.point, mid)

			results, err := Recover(context.Background(), r.paths.StateDir, r.host, r.out)
			if err != nil {
				t.Fatal(err)
			}
			if len(results) != 1 {
				t.Fatalf("results = %+v\n%s", results, r.out)
			}
			res := results[0]
			if res.Err != nil {
				t.Fatalf("recover: %v", res.Err)
			}
			st, err := LoadState(r.paths.StateDir, res.Op)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantCompleted {
				if res.Result != ResultCompletedAtBoot || st.Phase != PhaseDone {
					t.Fatalf("result %s, phase %s; want completed\n%s", res.Result, st.Phase, r.out)
				}
				r.assertInstalled(next, next.caddy)
				if !st.GatewayRestarted {
					t.Fatal("the pending gateway restart did not run at boot")
				}
				return
			}
			if res.Result != ResultRevertedAtBoot || st.Phase != PhaseFailed {
				t.Fatalf("result %s, phase %s; want reverted\n%s", res.Result, st.Phase, r.out)
			}
			r.assertInstalled(old, old.caddy)
			if res.RevertedSandboxd != tc.wantSelf {
				t.Fatalf("RevertedSandboxd = %v, want %v", res.RevertedSandboxd, tc.wantSelf)
			}
			if !strings.Contains(st.Error, "interrupted at") {
				t.Fatalf("error = %q", st.Error)
			}
			// Nothing is left half-written beside the binaries.
			for _, p := range []string{r.paths.Sandboxd, r.paths.Toolboxd, r.paths.Caddy} {
				if _, err := os.Stat(p + ".new"); err == nil {
					t.Fatalf("%s.new left behind", p)
				}
			}
		})
	}
}

// Recover leaves an op whose upgrader still runs to it, ignores finished
// ops, and does nothing on a node that never upgraded.
func TestRecoverLeavesWhatIsNotItsToTouch(t *testing.T) {
	r := newRig(t, newRelease("v0.6.11"))
	if res, err := Recover(context.Background(), r.paths.StateDir, r.host, r.out); err != nil || res != nil {
		t.Fatalf("no state directory: %v, %v", res, err)
	}
	if _, err := r.u.Run(context.Background(), r.from(newRelease("v0.6.12"))); err != nil {
		t.Fatal(err)
	}
	if res, err := Recover(context.Background(), r.paths.StateDir, r.host, r.out); err != nil || len(res) != 0 {
		t.Fatalf("a finished op was touched: %v, %v", res, err)
	}
	unfinished := &State{Format: stateFormat, Op: "op-live", Version: "v0.6.13", Phase: PhaseSwapping}
	if err := unfinished.save(r.paths.StateDir, r.now); err != nil {
		t.Fatal(err)
	}
	held, err := acquireLock(r.paths.StateDir, "op-live")
	if err != nil {
		t.Fatal(err)
	}
	if res, err := Recover(context.Background(), r.paths.StateDir, r.host, r.out); err != nil || res != nil {
		t.Fatalf("an op whose upgrader holds the lock was touched: %v, %v", res, err)
	}
	held.release()
	// A record that does not parse is skipped, not fatal.
	writeFile(t, statePath(r.paths.StateDir, "op-junk"), []byte("{"))
	res, err := Recover(context.Background(), r.paths.StateDir, r.host, r.out)
	if err != nil || len(res) != 1 || res[0].Op != "op-live" {
		t.Fatalf("after the lock: %+v, %v", res, err)
	}
}

// Completing at boot runs the restarts the dead upgrader had not reached
// and says when host apply is still owed; a restart that fails is reported.
func TestRecoverCompletesPendingWork(t *testing.T) {
	r := newRig(t, newRelease("v0.6.11"))
	next := newRelease("v0.6.12")
	writeFile(t, r.paths.Sandboxd, next.sandboxd)
	st := &State{Format: stateFormat, Op: "op-pending", Version: "v0.6.12", Phase: PhaseHost,
		HostApply: HostApplyPending, CaddyRestart: true, GatewayRestart: true,
		Files: []FileState{{Role: roleSandboxd, Path: r.paths.Sandboxd, SHA256: sum(next.sandboxd), Changed: true}}}
	if err := os.MkdirAll(r.paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := st.save(r.paths.StateDir, r.now); err != nil {
		t.Fatal(err)
	}
	r.host.fail["restart "+gatewayUnit] = errors.New("gateway down")
	res, err := Recover(context.Background(), r.paths.StateDir, r.host, r.out)
	if err != nil || len(res) != 1 {
		t.Fatalf("%v, %v", res, err)
	}
	if res[0].Err == nil || !strings.Contains(res[0].Err.Error(), "gateway down") {
		t.Fatalf("the failed restart was not reported: %v", res[0].Err)
	}
	r.order("restart caddy", "restart "+gatewayUnit)
	if !strings.Contains(r.out.String(), "sudo sandboxd host apply") {
		t.Fatalf("no host apply warning:\n%s", r.out)
	}
	got, _ := LoadState(r.paths.StateDir, "op-pending")
	if got.Phase != PhaseDone || !got.CaddyRestarted || got.GatewayRestarted {
		t.Fatalf("record = %+v", got)
	}
}

// A revert at boot that cannot put a file back (its .prev is not the file
// the op replaced) leaves it and says so.
func TestRecoverReportsAPrevItCannotTrust(t *testing.T) {
	r := newRig(t, newRelease("v0.6.11"))
	next := newRelease("v0.6.12")
	writeFile(t, r.paths.Toolboxd, next.toolboxd)
	writeFile(t, r.paths.Toolboxd+".prev", []byte("someone else's file"))
	st := &State{Format: stateFormat, Op: "op-bad-prev", Version: "v0.6.12", Phase: PhaseSwapping, CaddyRestarted: true,
		Files: []FileState{
			{Role: roleToolboxd, Path: r.paths.Toolboxd, SHA256: sum(next.toolboxd), PrevSHA256: sum(newRelease("v0.6.11").toolboxd), Changed: true},
			{Role: roleSandboxd, Path: r.paths.Sandboxd, SHA256: sum(next.sandboxd), PrevSHA256: sum(newRelease("v0.6.11").sandboxd), Changed: true},
		}}
	if err := os.MkdirAll(r.paths.StateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := st.save(r.paths.StateDir, r.now); err != nil {
		t.Fatal(err)
	}
	res, err := Recover(context.Background(), r.paths.StateDir, r.host, r.out)
	if err != nil || len(res) != 1 {
		t.Fatalf("%v, %v", res, err)
	}
	if res[0].Err == nil || !errors.Is(res[0].Err, errPrevMismatch) {
		t.Fatalf("err = %v, want a .prev mismatch", res[0].Err)
	}
	if readFile(t, r.paths.Toolboxd) != string(next.toolboxd) {
		t.Fatal("an untrusted .prev was installed")
	}
	r.order("restart caddy")
}
