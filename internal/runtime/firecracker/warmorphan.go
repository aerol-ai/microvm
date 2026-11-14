package firecracker

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	vmmpool "github.com/aerol-ai/microvm/internal/pool/vmm"
)

// CleanupOrphanSlot satisfies vmmpool.OrphanCleaner: the pool's GC calls
// it for a released warm slot it holds no handle for, before it deletes
// the slot's row.
func (s *PoolSpawner) CleanupOrphanSlot(ctx context.Context, slot vmmpool.Slot) error {
	if s == nil || s.driver == nil {
		return fmt.Errorf("firecracker pool spawner: driver is nil")
	}
	return s.driver.cleanupOrphanWarmSlot(ctx, slot)
}

// cleanupOrphanWarmSlot tears down what a released warm slot's row points
// to, without the slot's handle: a warm VM's handle does not survive a
// sandboxd restart. At boot AdoptRunningVMs kills an unclaimed warm VM
// (it has no record), but nothing removed its run dir or its TAP device,
// and the reap then deleted the only row that named them.
//
// Each step is a no-op once done, so a claimed slot, whose sandbox's
// destroy already removed all three, costs one socket dial and two
// lookups.
func (d *Driver) cleanupOrphanWarmSlot(ctx context.Context, slot vmmpool.Slot) error {
	// A VM still answering on the slot's socket is not torn down from
	// here: its handle is elsewhere (a sandbox whose destroy is still
	// being retried), and its run dir is in use. The row waits for it.
	if slot.APISocket != "" {
		answers, err := warmSocketAnswers(slot.APISocket)
		if err != nil {
			return fmt.Errorf("probe %s: %w", slot.APISocket, err)
		}
		if answers {
			return fmt.Errorf("a VM still answers on %s", slot.APISocket)
		}
	}
	// The TAP device, while its pool slot is still under the warm slot's
	// id. A claimed slot's TAP moved to its sandbox, whose destroy removes
	// it. The pool's reap releases the TAP slot itself after this returns.
	if d.pool != nil {
		tap, err := d.pool.Get(ctx, slot.ID)
		if err != nil {
			return fmt.Errorf("tap slot of %s: %w", slot.ID, err)
		}
		if tap != nil && d.tapHost != nil {
			if err := d.tapHost.Remove(ctx, tap.TapName); err != nil {
				return fmt.Errorf("remove tap %s: %w", tap.TapName, err)
			}
		}
	}
	if slot.RunDir == "" {
		return nil
	}
	// The same guard as vmm.Cleanup: never a path outside the run dir root.
	root := d.runDirRoot()
	if root == "" || !strings.HasPrefix(slot.RunDir, root+string(filepath.Separator)) {
		return fmt.Errorf("refusing to remove a run dir outside %q: %s", root, slot.RunDir)
	}
	if err := os.RemoveAll(slot.RunDir); err != nil {
		return err
	}
	removeJailDir(slot.RunDir, slot.ID)
	return nil
}

// warmSocketAnswers reports whether a process accepts connections on the
// API socket at path. A missing socket, a file that is not a socket, or a
// refused connection means no VM; any other failure is an unknown answer.
// A seam for tests.
var warmSocketAnswers = func(path string) (bool, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if info.Mode()&fs.ModeSocket == 0 {
		return false, nil
	}
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err == nil {
		_ = conn.Close()
		return true, nil
	}
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) {
		return false, nil
	}
	return false, err
}
