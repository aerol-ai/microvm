package wasm

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/wasm/worker"
)

// socketSpawner records the socket and the slot folder each Warm gets.
type socketSpawner struct {
	mu      sync.Mutex
	sockets []string
	dirs    []string
	stopped []string
}

func (s *socketSpawner) Warm(ctx context.Context, _, socketPath, _ string, _ int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sockets = append(s.sockets, socketPath)
	s.dirs = append(s.dirs, slotDirFrom(ctx, socketPath))
	return nil
}

func (s *socketSpawner) Shutdown(slotID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stopped = append(s.stopped, slotID)
	return nil
}

// helperSockets is a folder standing in for the root helper's WASM socket
// folder, with another host's socket in it.
func helperSockets(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	other := filepath.Join(dir, "w-another-host.sock")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir, other
}

// TestSlotsOnTheHelpersSocket: in privilege mode split a slot's worker
// serves the root helper's socket for the slot's id, while the slot keeps
// a folder of its own, which names its compile cache and goes with it. No
// removal of a slot ever reaches the helper's socket folder.
func TestSlotsOnTheHelpersSocket(t *testing.T) {
	sockets, other := helperSockets(t)
	run := t.TempDir()
	spawner := &socketSpawner{}
	p := New(run, nil)
	p.SetSpawner(spawner)
	p.SetSocketFor(func(slotID string) (string, error) { return filepath.Join(sockets, "w-"+slotID+".sock"), nil })
	slots := make([]*Slot, 3)
	for i := range slots {
		slot, err := p.WarmOne(context.Background(), "digest-a", "/mod.wasm")
		if err != nil {
			t.Fatal(err)
		}
		slots[i] = slot
		if want := filepath.Join(sockets, "w-"+slot.ID+".sock"); slot.SocketPath != want || spawner.sockets[i] != want {
			t.Fatalf("slot socket %s, spawner got %s, want %s", slot.SocketPath, spawner.sockets[i], want)
		}
		if slot.Dir != p.SlotDir("digest-a", slot.ID) || slot.Folder() != slot.Dir || spawner.dirs[i] != slot.Dir {
			t.Fatalf("slot folder %q, spawner's %q", slot.Dir, spawner.dirs[i])
		}
		if st, err := os.Stat(slot.Dir); err != nil || !st.IsDir() {
			t.Fatalf("slot folder not made: %v", err)
		}
	}
	// Each way a slot goes removes its own folder, never the socket's.
	p.RecordLoaded(slots[0])
	p.DropModule("digest-a")
	p.NoteModule("digest-b", "/mod.wasm")
	slots[1].ModuleDigest = "digest-b"
	p.RecordLoaded(slots[1])
	if drained := p.Close(); drained != 1 {
		t.Fatalf("drained %d", drained)
	}
	p.RecordLoaded(slots[2]) // after Close: shut down at once
	for _, slot := range slots {
		if _, err := os.Stat(slot.Dir); !os.IsNotExist(err) {
			t.Fatalf("slot folder %s left: %v", slot.Dir, err)
		}
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("the helper's socket folder was touched: %v", err)
	}
	if len(spawner.stopped) != 3 {
		t.Fatalf("stopped %v", spawner.stopped)
	}
}

// TestSlotSocketRefused: a slot id the helper's socket rule refuses warms
// nothing and leaves no folder.
func TestSlotSocketRefused(t *testing.T) {
	run := t.TempDir()
	spawner := &socketSpawner{}
	p := New(run, nil)
	p.SetSpawner(spawner)
	p.SetSocketFor(func(string) (string, error) { return "", errors.New("too long") })
	if _, err := p.WarmOne(context.Background(), "digest-a", "/mod.wasm"); err == nil {
		t.Fatal("warmed a slot with no socket")
	}
	if len(spawner.sockets) != 0 {
		t.Fatal("spawned with no socket")
	}
	if entries, _ := os.ReadDir(run); len(entries) != 0 {
		t.Fatalf("left %v", entries)
	}
}

// TestSlotFolder: a slot made without a folder (before this field, or by
// a test) is its socket's folder, and a slot with neither has none.
func TestSlotFolder(t *testing.T) {
	for _, tc := range []struct {
		slot Slot
		want string
	}{
		{Slot{Dir: "/run/pool/d/s", SocketPath: "/helper/w-s.sock"}, "/run/pool/d/s"},
		{Slot{SocketPath: "/run/pool/d/s/worker.sock"}, "/run/pool/d/s"},
		{Slot{}, ""},
	} {
		if got := tc.slot.Folder(); got != tc.want {
			t.Errorf("Folder(%+v) = %q, want %q", tc.slot, got, tc.want)
		}
	}
	if !IsSlotID(NewSlotID()) || IsSlotID("sb-1") || IsSlotID("pool-xyz") {
		t.Fatal("slot id shape")
	}
	if SlotDirIn("/run", "0123456789abcdef", "pool-0123456789abcdef") != "/run/pool/0123456789ab/pool-0123456789abcdef" {
		t.Fatal("slot dir")
	}
}

// TestSupervisorSpawnerCacheByTheSlotFolder: a slot whose socket is the
// helper's gets the compile cache of its own folder, never one keyed by
// the helper's socket folder, which every slot shares.
func TestSupervisorSpawnerCacheByTheSlotFolder(t *testing.T) {
	sockets, _ := helperSockets(t)
	slotDir := t.TempDir()
	var got string
	sup := worker.NewSupervisor(func(ctx context.Context, _ string) (*exec.Cmd, error) {
		got = worker.CompileCacheOf(ctx)
		return nil, errSpawnFail
	})
	ss := NewSupervisorSpawner(sup)
	ss.CompileCache = func(dir string) string { return filepath.Join(dir, "cache") }
	_ = ss.Warm(WithSlotDir(context.Background(), slotDir), "pool-0123456789abcdef", filepath.Join(sockets, "w-pool-0123456789abcdef.sock"), "/mod.wasm", 0)
	if want := filepath.Join(slotDir, "cache"); got != want {
		t.Fatalf("worker cache %q, want %q", got, want)
	}
}
