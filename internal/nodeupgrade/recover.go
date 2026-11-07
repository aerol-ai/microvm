package nodeupgrade

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
)

// RecoverResult is what boot recovery did with one unfinished op.
type RecoverResult struct {
	Op     string
	Result string // ResultCompletedAtBoot or ResultRevertedAtBoot
	// RevertedSandboxd is true when the sandboxd binary itself was put
	// back: the process that ran recovery is the newer binary and must
	// exit so systemd starts the previous one.
	RevertedSandboxd bool
	Err              error
}

// Recover resolves every unfinished upgrade in stateDir at sandboxd start
// (§6.3, "a reboot mid-swap"): an op whose new files are all in place is
// marked done, and any other has the files it already swapped put back and
// is marked failed, so a node never runs a half-swapped set. An op whose
// upgrader still holds the lock is left to it. It never restores a
// database backup: it cannot tell what the new binary did.
func Recover(ctx context.Context, stateDir string, host Host, out io.Writer) ([]RecoverResult, error) {
	if _, err := os.Stat(stateDir); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	lk, err := acquireLock(stateDir, "")
	if err != nil {
		if errors.Is(err, ErrBusy) {
			// The upgrader that started this sandboxd is still running.
			return nil, nil
		}
		return nil, err
	}
	defer lk.release()
	states, err := listStates(stateDir)
	if err != nil {
		return nil, err
	}
	u := &Upgrader{Paths: Paths{StateDir: stateDir}, Host: host, Out: out}
	var results []RecoverResult
	for _, st := range states {
		if st.terminal() {
			continue
		}
		reverted, err := u.resolve(ctx, st)
		results = append(results, RecoverResult{Op: st.Op, Result: st.Result, RevertedSandboxd: reverted, Err: err})
	}
	return results, nil
}

// resolve finishes an op whose upgrader is gone. It reports whether it put
// the sandboxd binary back.
func (u *Upgrader) resolve(ctx context.Context, st *State) (bool, error) {
	phase := st.Phase
	var problems []error
	revertedSandboxd := false
	if phase != PhaseRevert && allNewInPlace(st) {
		if st.CaddyRestart && !st.CaddyRestarted {
			if err := u.Host.RestartUnit(ctx, caddyUnit); err != nil {
				problems = append(problems, err)
			} else {
				st.CaddyRestarted = true
			}
		}
		if st.GatewayRestart && !st.GatewayRestarted {
			if err := u.Host.RestartUnit(ctx, gatewayUnit); err != nil {
				problems = append(problems, err)
			} else {
				st.GatewayRestarted = true
			}
		}
		if st.HostApply == HostApplyPending {
			u.logf("warning: upgrade op %s finished at boot without its host setup; run `sudo sandboxd host apply` and restart sandboxd", st.Op)
		}
		st.Phase, st.Result = PhaseDone, ResultCompletedAtBoot
		u.logf("upgrade op %s to %s was interrupted at %s with every new file in place; marked done", st.Op, st.Version, phase)
	} else {
		// A revert under way is carried on; anything else short of every
		// new file is undone.
		for i := len(swapOrder) - 1; i >= 0; i-- {
			f := st.file(swapOrder[i])
			if f == nil || !f.Changed {
				continue
			}
			cur, err := fileSHA256(f.Path)
			if err != nil {
				problems = append(problems, err)
				continue
			}
			if cur != f.SHA256 {
				continue // never swapped, or already put back
			}
			if err := putBack(f.Path, f.PrevSHA256); err != nil {
				problems = append(problems, fmt.Errorf("put back %s: %w", f.Path, err))
				continue
			}
			f.Swapped = false
			if f.Role == roleSandboxd {
				revertedSandboxd = true
			}
		}
		// Services restarted onto the new files run them; restart them
		// onto the old ones.
		if st.GatewayRestarted {
			if err := u.Host.RestartUnit(ctx, gatewayUnit); err != nil {
				problems = append(problems, err)
			}
		}
		if st.CaddyRestarted {
			if err := u.Host.RestartUnit(ctx, caddyUnit); err != nil {
				problems = append(problems, err)
			}
		}
		msg := fmt.Sprintf("interrupted at %s; the files it had swapped were put back", phase)
		if st.Error != "" {
			msg = st.Error + "; " + msg
		}
		st.Phase, st.Result, st.Error = PhaseFailed, ResultRevertedAtBoot, msg
		u.logf("upgrade op %s to %s was interrupted at %s; put the previous files back", st.Op, st.Version, phase)
	}
	// A copy a crash left half-way beside an installed file.
	for _, f := range st.Files {
		if f.Path != "" {
			_ = os.Remove(f.Path + ".new")
		}
	}
	if err := u.save(st); err != nil {
		problems = append(problems, err)
	}
	return revertedSandboxd, errors.Join(problems...)
}

// allNewInPlace reports whether every file the op changes is installed
// with its new content. sandboxd is swapped last, so a new sandboxd on
// disk normally means the rest are new too.
func allNewInPlace(st *State) bool {
	for _, f := range st.Files {
		if f.Path == "" || !f.Changed {
			continue
		}
		if cur, _ := fileSHA256(f.Path); cur != f.SHA256 {
			return false
		}
	}
	return true
}
