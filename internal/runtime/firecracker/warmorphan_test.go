package firecracker

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	vmmpool "github.com/aerol-ai/microvm/internal/pool/vmm"
)

// A released warm slot with no handle (a restart left it) has its TAP
// device and run dir removed before the pool deletes its row; a claimed
// slot, already torn down by its sandbox's destroy, costs nothing; and a
// VM still answering on the socket, or anything that cannot be removed,
// keeps the row.
func TestCleanupOrphanWarmSlot(t *testing.T) {
	cases := []struct {
		name string
		// setup prepares the slot; it returns the slot to tear down.
		setup         func(t *testing.T, f *driverFixture) vmmpool.Slot
		answers       bool
		probeErr      error
		wantErr       bool
		wantTapRemove int
		wantDirGone   bool
	}{
		{
			name: "left by a restart",
			setup: func(t *testing.T, f *driverFixture) vmmpool.Slot {
				f.pool.slots["vmms-a"] = &TapSlot{TapName: "fctap7"}
				return orphanSlot(t, f, "vmms-a", true)
			},
			wantTapRemove: 1, wantDirGone: true,
		},
		{
			name: "claimed: its sandbox's destroy removed everything",
			setup: func(t *testing.T, f *driverFixture) vmmpool.Slot {
				return orphanSlot(t, f, "vmms-a", false)
			},
			wantDirGone: true,
		},
		{
			name: "a VM still answers on the socket",
			setup: func(t *testing.T, f *driverFixture) vmmpool.Slot {
				f.pool.slots["vmms-a"] = &TapSlot{TapName: "fctap7"}
				return orphanSlot(t, f, "vmms-a", true)
			},
			answers: true, wantErr: true,
		},
		{
			name: "the probe cannot tell",
			setup: func(t *testing.T, f *driverFixture) vmmpool.Slot {
				return orphanSlot(t, f, "vmms-a", true)
			},
			probeErr: errors.New("permission denied"), wantErr: true,
		},
		{
			name: "the TAP device cannot be removed",
			setup: func(t *testing.T, f *driverFixture) vmmpool.Slot {
				f.pool.slots["vmms-a"] = &TapSlot{TapName: "fctap7"}
				f.tapHost.removeErr = errors.New("device busy")
				return orphanSlot(t, f, "vmms-a", true)
			},
			wantErr: true, wantTapRemove: 1,
		},
		{
			name: "the TAP slot cannot be read",
			setup: func(t *testing.T, f *driverFixture) vmmpool.Slot {
				f.pool.getErr = errors.New("store closed")
				return orphanSlot(t, f, "vmms-a", true)
			},
			wantErr: true,
		},
		{
			name: "a slot that never had a run dir",
			setup: func(t *testing.T, f *driverFixture) vmmpool.Slot {
				f.pool.slots["vmms-a"] = &TapSlot{TapName: "fctap7"}
				return vmmpool.Slot{ID: "vmms-a"}
			},
			wantTapRemove: 1,
		},
		{
			name: "the run dir cannot be removed",
			setup: func(t *testing.T, f *driverFixture) vmmpool.Slot {
				slot := orphanSlot(t, f, "vmms-a", true)
				// A read-only directory inside refuses its file's removal,
				// as a root-owned jail tree does for sandboxd's user.
				locked := filepath.Join(slot.RunDir, "jail")
				if err := os.MkdirAll(locked, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(locked, "f"), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(locked, 0o555); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
				if f, err := os.CreateTemp(locked, "probe"); err == nil {
					_ = f.Close()
					t.Skip("running as root: a read-only directory does not refuse changes")
				}
				return slot
			},
			wantErr: true,
		},
		{
			name: "a run dir outside the root",
			setup: func(t *testing.T, f *driverFixture) vmmpool.Slot {
				slot := orphanSlot(t, f, "vmms-a", true)
				outside := filepath.Join(t.TempDir(), "vmms-a")
				if err := os.MkdirAll(outside, 0o755); err != nil {
					t.Fatal(err)
				}
				slot.RunDir = outside
				return slot
			},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newDriverFixture(t)
			slot := tc.setup(t, f)
			defer func(orig func(string) (bool, error)) { warmSocketAnswers = orig }(warmSocketAnswers)
			if tc.answers || tc.probeErr != nil {
				warmSocketAnswers = func(string) (bool, error) { return tc.answers, tc.probeErr }
			}

			err := NewPoolSpawner(f.driver).CleanupOrphanSlot(context.Background(), slot)
			if (err != nil) != tc.wantErr {
				t.Fatalf("CleanupOrphanSlot = %v, want error=%v", err, tc.wantErr)
			}
			if f.tapHost.removeCalls != tc.wantTapRemove {
				t.Fatalf("TAP removes = %d, want %d", f.tapHost.removeCalls, tc.wantTapRemove)
			}
			if slot.RunDir == "" {
				return
			}
			_, statErr := os.Stat(slot.RunDir)
			if gone := os.IsNotExist(statErr); gone != tc.wantDirGone {
				t.Fatalf("run dir gone = %v (%v), want %v", gone, statErr, tc.wantDirGone)
			}
		})
	}

	var nilSpawner *PoolSpawner
	if err := nilSpawner.CleanupOrphanSlot(context.Background(), vmmpool.Slot{}); err == nil {
		t.Fatal("a nil spawner tore something down")
	}
}

// orphanSlot is a released warm slot's row; with withDir its run dir is
// still on disk, holding an API socket file no VM listens on.
func orphanSlot(t *testing.T, f *driverFixture, id string, withDir bool) vmmpool.Slot {
	t.Helper()
	dir := filepath.Join(f.runDir, id)
	slot := vmmpool.Slot{ID: id, RunDir: dir, APISocket: filepath.Join(dir, "api.sock")}
	if withDir {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, vmmOutputName), []byte("boot log"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return slot
}

func TestWarmSocketAnswers(t *testing.T) {
	dir, err := os.MkdirTemp("", "ws")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	path := filepath.Join(dir, "api.sock")
	if answers, err := warmSocketAnswers(path); answers || err != nil {
		t.Fatalf("missing socket = %v, %v; want no VM", answers, err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("unix socket: %v", err)
	}
	if answers, err := warmSocketAnswers(path); !answers || err != nil {
		t.Fatalf("listening socket = %v, %v; want a VM", answers, err)
	}
	// A socket this user may not connect to is an unknown answer, not "no
	// VM": the reaper must not remove a run dir it cannot see into.
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatal(err)
	}
	if answers, err := warmSocketAnswers(path); os.Getuid() != 0 && (answers || err == nil) {
		t.Fatalf("socket with no access = %v, %v; want an unknown answer", answers, err)
	}
	if err := os.Chmod(path, 0o755); err != nil {
		t.Fatal(err)
	}
	// A socket file left behind with no listener refuses connections.
	ln.(*net.UnixListener).SetUnlinkOnClose(false)
	_ = ln.Close()
	if answers, err := warmSocketAnswers(path); answers || err != nil {
		t.Fatalf("stale socket = %v, %v; want no VM", answers, err)
	}

	// A regular file where the socket should be is no VM.
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if answers, err := warmSocketAnswers(plain); answers || err != nil {
		t.Fatalf("regular file = %v, %v; want no VM", answers, err)
	}
	// A path that cannot be looked at (a file in place of its directory)
	// is an unknown answer.
	if answers, err := warmSocketAnswers(filepath.Join(plain, "api.sock")); answers || err == nil {
		t.Fatalf("unreadable path = %v, %v; want an unknown answer", answers, err)
	}
}
