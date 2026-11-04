package mounts

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts/adapters"
)

func TestMountAllWaitingForSweepHonoursContext(t *testing.T) {
	m := newTestManager(t, map[models.MountType]adapters.Adapter{models.MountTypeS3: fakeAdapter{}})
	done, _ := m.claimOrphan("sb-held")
	t.Cleanup(func() { m.releaseOrphan("sb-held", done) })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := m.MountAll(ctx, "sb-held", s3Spec)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("MountAll = %v, want the context's deadline", err)
	}
	if _, statErr := os.Stat(filepath.Join(m.rootDir, "sb-held")); !os.IsNotExist(statErr) {
		t.Fatalf("a cancelled MountAll created the directory: %v", statErr)
	}
}

// Behaviour that must not change: a directory nobody owns is still swept, at
// boot and on every periodic reconcile.
func TestSweepOwnership(t *testing.T) {
	cases := []struct {
		name     string
		keep     bool
		own      func(m *Manager, id string) (undo func())
		wantKept bool
	}{
		{name: "orphan is removed"},
		{name: "keep-listed sandbox survives", keep: true, wantKept: true},
		{name: "tracked mounts survive", wantKept: true, own: func(m *Manager, id string) func() {
			m.mu.Lock()
			m.state[id] = []*mountState{{sandboxID: id}}
			m.mu.Unlock()
			return func() {}
		}},
		{name: "mount in flight survives", wantKept: true, own: func(m *Manager, id string) func() {
			release, _ := m.beginMount(context.Background(), id)
			return release
		}},
		{name: "two mounts in flight, one returned, survives", wantKept: true, own: func(m *Manager, id string) func() {
			first, _ := m.beginMount(context.Background(), id)
			second, _ := m.beginMount(context.Background(), id)
			first()
			return second
		}},
		{name: "claimed by a concurrent sweep is left to it", wantKept: true, own: func(m *Manager, id string) func() {
			done, _ := m.claimOrphan(id)
			return func() { m.releaseOrphan(id, done) }
		}},
		{name: "orphan whose mount already returned is removed", own: func(m *Manager, id string) func() {
			release, _ := m.beginMount(context.Background(), id)
			release()
			return func() {}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := newTestManager(t, nil)
			const id = "sb-sweep"
			dir := filepath.Join(m.rootDir, id)
			if err := os.MkdirAll(filepath.Join(dir, "0"), 0o700); err != nil {
				t.Fatal(err)
			}
			undo := func() {}
			if tc.own != nil {
				undo = tc.own(m, id)
			}
			keep := map[string]struct{}{}
			if tc.keep {
				keep[id] = struct{}{}
			}
			m.Sweep(keep)
			_, err := os.Stat(dir)
			if kept := err == nil; kept != tc.wantKept {
				t.Fatalf("kept = %v (stat err %v), want %v", kept, err, tc.wantKept)
			}
			undo()
			m.mu.Lock()
			defer m.mu.Unlock()
			if len(m.mounting) != 0 || len(m.sweeping) != 0 {
				t.Fatalf("claims left behind: mounting=%v sweeping=%v", m.mounting, m.sweeping)
			}
		})
	}
}
