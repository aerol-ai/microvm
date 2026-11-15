package safety

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// gitThatFails puts a git first on PATH that fails the subcommand matching
// failOn and runs the real git for everything else, so a lease or claim
// meets the git error it would see on a broken or busy checkout.
func gitThatFails(t *testing.T, failOn string) []string {
	t.Helper()
	real, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not on PATH")
	}
	bin := t.TempDir()
	mustWrite(t, filepath.Join(bin, "git"), fmt.Sprintf(`#!/bin/sh
case "$*" in *%q*) echo "git: injected failure" >&2; exit 128;; esac
exec %q "$@"
`, failOn, real))
	if err := os.Chmod(filepath.Join(bin, "git"), 0o755); err != nil {
		t.Fatal(err)
	}
	return append(gitEnv(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// Inside a git checkout, a git that cannot answer must stop the lease and the
// claim. Before, a failed `rev-parse --git-common-dir` fell back to a lock
// under the worktree's own .tf, which no other worktree takes, and a failed
// `worktree list` read as "no other worktrees": either way two worktrees
// could take the same domain or scenario.
func TestLeaseAndClaimRefuseWhenGitFails(t *testing.T) {
	requireYQ(t)
	for _, failOn := range []string{"rev-parse --git-common-dir", "worktree list"} {
		t.Run(failOn, func(t *testing.T) {
			a, b := twoWorktrees(t)
			// b is live on one.itest, under the same scenario name.
			pinDomain(t, b, "s", "one.itest.example.com")
			env := gitThatFails(t, failOn)

			stdout, stderr, code := runBashScript(t, leaseScript(leaseFuncs(t), "s"), a, env)
			if code == 0 || stdout != "" {
				t.Fatalf("lease = %q (exit %d) while git %s fails; want a refusal", stdout, code, failOn)
			}
			if !strings.Contains(stderr, "failed") {
				t.Errorf("the refusal does not say git failed:\n%s", stderr)
			}
			if _, err := os.Stat(filepath.Join(a, "integration-tests", ".tf", "s", ".leased-domain")); !os.IsNotExist(err) {
				t.Errorf("a refused lease wrote a pin (stat err %v)", err)
			}

			writeClaim(t, b, "s")
			_, _, code = runBashScript(t, claimScript(claimFuncs(t), "s"), a, env)
			if code == 0 {
				t.Fatalf("claim granted while git %s fails and worktree b holds s", failOn)
			}
			if _, err := os.Stat(claimPath(a, "s")); !os.IsNotExist(err) {
				t.Errorf("a refused claim wrote its claim (stat err %v)", err)
			}

			for _, lock := range []string{
				filepath.Join(a, ".git", "aerol-itest-domain-lease.lock"),
				filepath.Join(a, "integration-tests", ".tf", ".domain-lease.lock"),
			} {
				if _, err := os.Stat(lock); !os.IsNotExist(err) {
					t.Errorf("a refusal left %s behind (stat err %v)", lock, err)
				}
			}
		})
	}
}

// heldLock makes the shared lease lock as a run would, owned by pid, with
// its mtime set to mtime.
func heldLock(t *testing.T, a string, pid int, mtime time.Time) string {
	t.Helper()
	host, err := exec.Command("uname", "-n").Output()
	if err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(a, ".git", "aerol-itest-domain-lease.lock")
	mustMkdir(t, lock)
	mustWrite(t, filepath.Join(lock, "owner"), fmt.Sprintf("%d %s\n", pid, strings.TrimSpace(string(host))))
	if err := os.Chtimes(lock, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	return lock
}

// A lock whose holder is still running is never cleared, however old its
// timestamp: a clock that jumps forward makes a fresh lock look old, and the
// old check (age alone) then let a second run in beside the holder. Once the
// holder is gone, the next lease clears the lock at once.
func TestLeaseLockFollowsItsHolderNotTheClock(t *testing.T) {
	requireYQ(t)
	a, b := twoWorktrees(t)
	holder := exec.Command("sleep", "60")
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Process.Kill(); _, _ = holder.Process.Wait() }()
	lock := heldLock(t, a, holder.Process.Pid, time.Now().Add(-10*time.Minute))

	cmd := exec.Command("bash", "-c", leaseScript(leaseFuncs(t), "s"), "bash", b)
	cmd.Env = gitEnv()
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		t.Fatalf("the lease finished (%v, %q) while a live run held a lock stamped 10 minutes ago", err, out.String())
	case <-time.After(1500 * time.Millisecond):
	}
	if _, err := os.Stat(filepath.Join(lock, "owner")); err != nil {
		t.Fatalf("the live holder's lock was cleared: %v", err)
	}

	_ = holder.Process.Kill()
	_, _ = holder.Process.Wait()
	select {
	case err := <-done:
		if err != nil || !strings.Contains(out.String(), "itest.example.com") {
			t.Fatalf("after the holder died: %v, leased %q", err, out.String())
		}
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the lease did not clear a dead holder's lock")
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Errorf("the lease lock is still there after the lease (stat err %v)", err)
	}
}

// A lock left by a run that is gone is cleared without waiting a minute for
// its timestamp to age.
func TestLeaseClearsADeadHoldersFreshLockAtOnce(t *testing.T) {
	requireYQ(t)
	a, _ := twoWorktrees(t)
	gone := exec.Command("true")
	if err := gone.Run(); err != nil {
		t.Fatal(err)
	}
	heldLock(t, a, gone.Process.Pid, time.Now())
	start := time.Now()
	stdout, stderr, code := runBashScript(t, leaseScript(leaseFuncs(t), "s"), a, gitEnv())
	if code != 0 || !strings.Contains(stdout, "itest.example.com") {
		t.Fatalf("lease = %q (exit %d): %s", stdout, code, stderr)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("clearing a dead holder's lock took %s; want no wait for its age", took)
	}
}

// A lease runs inside run_one's $(…). If that subshell dies mid-lease while
// run.sh goes on, the lock must name the dead subshell, not the live parent,
// or every other run waits its 3 minutes and fails for the rest of that run.
// bash 3.2 has no BASHPID, so there the parent is recorded and the lock
// clears once run.sh exits; the test needs bash 4 or newer.
func TestLeaseLockOfADeadLeaseSubshellIsClearedAtOnce(t *testing.T) {
	requireYQ(t)
	if out, err := exec.Command("bash", "-c", `printf %s "${BASHPID:-}"`).Output(); err != nil || len(out) == 0 {
		t.Skip("this bash has no BASHPID (bash 3.2): a lease records its parent run there")
	}
	a, b := twoWorktrees(t)
	holder := exec.Command("bash", "-c", `set -euo pipefail
REPO_ROOT="$1"
`+leaseFuncs(t)+`
( lease_lock_acquire ) # the lease subshell takes the lock and dies without releasing
echo held
sleep 60 # the run goes on
`, "bash", a)
	holder.Env = gitEnv()
	var held strings.Builder
	holder.Stdout = &held
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Process.Kill(); _, _ = holder.Process.Wait() }()
	deadline := time.Now().Add(15 * time.Second)
	for !strings.Contains(held.String(), "held") {
		if time.Now().After(deadline) {
			t.Fatal("the holder never took the lock")
		}
		time.Sleep(50 * time.Millisecond)
	}
	owner, err := os.ReadFile(filepath.Join(a, ".git", "aerol-itest-domain-lease.lock", "owner"))
	if err != nil {
		t.Fatalf("no owner file in the lock the subshell left: %v", err)
	}
	if strings.HasPrefix(string(owner), fmt.Sprintf("%d ", holder.Process.Pid)) {
		t.Fatalf("the lock names the live parent run (%q), not the dead lease subshell", owner)
	}

	start := time.Now()
	stdout, stderr, code := runBashScript(t, leaseScript(leaseFuncs(t), "s"), b, gitEnv())
	if code != 0 || !strings.Contains(stdout, "itest.example.com") {
		t.Fatalf("lease = %q (exit %d) beside a lock its dead subshell left: %s", stdout, code, stderr)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("clearing the dead subshell's lock took %s; want no wait", took)
	}
}

// mkdirThatAlwaysWins puts a mkdir first on PATH that reports success even
// when the directory is already there, which is what uutils coreutils' mkdir
// (Ubuntu 26.04's default, and the CI runners') does for two calls racing on
// one path. With it, mkdir decides nothing, so a test sees whether the lock
// still holds.
func mkdirThatAlwaysWins(t *testing.T) []string {
	t.Helper()
	real, err := exec.LookPath("mkdir")
	if err != nil {
		t.Skip("mkdir not on PATH")
	}
	bin := t.TempDir()
	mustWrite(t, filepath.Join(bin, "mkdir"), fmt.Sprintf("#!/bin/sh\nfor a in \"$@\"; do case \"$a\" in -*) ;; *) [ -d \"$a\" ] && continue; %q -p \"$a\" || exit 1;; esac; done\n", real))
	if err := os.Chmod(filepath.Join(bin, "mkdir"), 0o755); err != nil {
		t.Fatal(err)
	}
	return append(gitEnv(), "PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// The lock is the owner file bash creates with noclobber (O_EXCL), not the
// mkdir: on CI, uutils' mkdir let two racing runs both "make" the lock
// directory, and both leased the same domain (2026-11-15). A second run must
// wait for a live holder even when its mkdir says it made the directory.
func TestLeaseLockHoldsWhenMkdirDoesNot(t *testing.T) {
	requireYQ(t)
	a, b := twoWorktrees(t)
	holder := exec.Command("sleep", "60")
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = holder.Process.Kill(); _, _ = holder.Process.Wait() }()
	heldLock(t, a, holder.Process.Pid, time.Now())

	cmd := exec.Command("bash", "-c", leaseScript(leaseFuncs(t), "s"), "bash", b)
	cmd.Env = mkdirThatAlwaysWins(t)
	var out strings.Builder
	cmd.Stdout = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		t.Fatalf("the lease finished (%v, %q) while a live run held the lock: it trusted mkdir", err, out.String())
	case <-time.After(1500 * time.Millisecond):
	}
	_ = holder.Process.Kill()
	_, _ = holder.Process.Wait()
	select {
	case err := <-done:
		if err != nil || !strings.Contains(out.String(), "itest.example.com") {
			t.Fatalf("after the holder died: %v, leased %q", err, out.String())
		}
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("the lease did not go on once the holder died")
	}
}

// Two runs racing with a mkdir that always reports success still get one
// domain each and one claim between them, round after round.
func TestConcurrentLeasesAndClaimsHoldWhenMkdirDoesNot(t *testing.T) {
	requireYQ(t)
	a, b := twoWorktrees(t)
	env := mkdirThatAlwaysWins(t)
	leaseFns, claimFns := leaseFuncs(t), claimFuncs(t)
	for round := range 10 {
		for _, root := range []string{a, b} {
			if err := os.RemoveAll(filepath.Join(root, "integration-tests", ".tf")); err != nil {
				t.Fatal(err)
			}
		}
		outs := make([]strings.Builder, 2)
		cmds := make([]*exec.Cmd, 2)
		for i, root := range []string{a, b} {
			cmds[i] = exec.Command("bash", "-c", leaseScript(leaseFns, "s"), "bash", root)
			cmds[i].Env = env
			cmds[i].Stdout = &outs[i]
			if err := cmds[i].Start(); err != nil {
				t.Fatal(err)
			}
		}
		for i, c := range cmds {
			if err := c.Wait(); err != nil {
				t.Fatalf("round %d: lease %d failed: %v", round, i, err)
			}
		}
		if x, y := strings.TrimSpace(outs[0].String()), strings.TrimSpace(outs[1].String()); x == y {
			t.Fatalf("round %d: both worktrees leased %q", round, x)
		}

		for _, root := range []string{a, b} {
			if err := os.RemoveAll(filepath.Join(root, "integration-tests", ".tf")); err != nil {
				t.Fatal(err)
			}
		}
		granted := 0
		for i, root := range []string{a, b} {
			cmds[i] = exec.Command("bash", "-c", claimScript(claimFns, "s"), "bash", root)
			cmds[i].Env = env
			if err := cmds[i].Start(); err != nil {
				t.Fatal(err)
			}
		}
		for _, c := range cmds {
			if c.Wait() == nil {
				granted++
			}
		}
		if granted != 1 {
			t.Fatalf("round %d: %d worktrees got scenario s; want exactly 1", round, granted)
		}
	}
}
