package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A snapshot of a running Firecracker sandbox copies its live disk while the
// guest holds the root filesystem frozen, then thaws it. What matters: the
// copy is made between freeze and thaw, the sandbox is always thawed and
// keeps running, an agent that cannot freeze gets the right 409, and a Stop
// never runs while the filesystem is frozen.

// runningSandboxForSnapshot creates a running sandbox with an image store and
// the helper VM stand-in wired in. Its live disk holds known bytes.
func runningSandboxForSnapshot(t *testing.T, id string) (*driverFixture, *recordingImageStore, *exportGuest, string) {
	t.Helper()
	f := stoppedFixtureSandbox(t, id)
	store := &recordingImageStore{}
	guest := &exportGuest{t: t, fill: guestTree}
	f.driver.SetImageStore(store)
	f.driver.mu.Lock()
	handle := f.driver.vmms[id]
	f.driver.mu.Unlock()
	live := filepath.Join(handle.RunDir(), rootfsFileName)
	if err := os.WriteFile(live, []byte("live disk bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	// After the sandbox's own create: the stand-in routes only the helper.
	guest.install(f)
	return f, store, guest, live
}

// opsSince lists the vsock ops sent after the first n writes.
func opsSince(t *testing.T, f *driverFixture, n int) []string {
	t.Helper()
	return vsockOps(t, f.vsock)[n:]
}

func exportCopies(t *testing.T, f *driverFixture) []string {
	t.Helper()
	base, _ := f.driver.snapshotExportDir()
	matches, _ := filepath.Glob(filepath.Join(base, "*", exportDiskFileName))
	return matches
}

func TestCreateSnapshotOfARunningSandboxFreezesForTheCopy(t *testing.T) {
	f, store, guest, live := runningSandboxForSnapshot(t, "sb-live")
	var copiedWhileFrozen bool
	f.vsock.replyFor = func(op string) (bool, string) {
		if op == "thaw_fs" {
			// The copy exists, with the live disk's bytes, before the thaw.
			for _, c := range exportCopies(t, f) {
				if b, _ := os.ReadFile(c); bytes.Equal(b, []byte("live disk bytes")) {
					copiedWhileFrozen = true
				}
			}
		}
		return true, ""
	}
	before := len(vsockOps(t, f.vsock))

	id, err := f.driver.CreateSnapshot(context.Background(), "sb-live", "aerolvm-snapshot/live:latest")
	if err != nil {
		t.Fatalf("CreateSnapshot of a running sandbox: %v", err)
	}
	if id != "sha256:img-aerolvm-snapshot/live:latest" {
		t.Fatalf("id = %q", id)
	}
	if ops := opsSince(t, f, before); strings.Join(ops, ",") != "freeze_fs,thaw_fs" {
		t.Fatalf("ops = %v, want freeze_fs then thaw_fs", ops)
	}
	if !copiedWhileFrozen {
		t.Fatal("the disk was not copied between freeze_fs and thaw_fs")
	}
	// The freeze tells the guest when to thaw on its own.
	var freeze struct {
		Data struct {
			ThawAfterMS int64 `json:"thaw_after_ms"`
		} `json:"data"`
	}
	for _, w := range f.vsock.snapshotWrites() {
		if bytes.Contains(w, []byte(`"freeze_fs"`)) {
			_ = json.Unmarshal(w, &freeze)
		}
	}
	if freeze.Data.ThawAfterMS != guestFreezeLimit.Milliseconds() {
		t.Fatalf("freeze_fs thaw_after_ms = %d, want %d", freeze.Data.ThawAfterMS, guestFreezeLimit.Milliseconds())
	}
	// The helper VM read the copy, never the live disk, and both the VM and
	// its disk were left alone.
	if disk := guest.lastClient().drives[exportDriveID].PathOnHost; disk == live || string(guest.disks[0]) != "live disk bytes" {
		t.Fatalf("the helper read %q (%q), want a copy of %q", disk, guest.disks[0], live)
	}
	if b, _ := os.ReadFile(live); string(b) != "live disk bytes" {
		t.Fatalf("the live disk changed: %q", b)
	}
	f.driver.mu.Lock()
	_, stillRunning := f.driver.vmms["sb-live"]
	f.driver.mu.Unlock()
	if !stillRunning {
		t.Fatal("the sandbox is no longer running after its snapshot")
	}
	headers, _ := tarEntries(t, store.imported["aerolvm-snapshot/live:latest"])
	if _, ok := headers["etc/os-release"]; !ok {
		t.Fatal("the image holds no files")
	}
	if left := exportCopies(t, f); len(left) != 0 {
		t.Fatalf("export copy left behind: %v", left)
	}
}

// An agent from before freeze_fs cannot pause the sandbox, and never will.
func TestCreateSnapshotOfARunningSandboxWithAnOldAgent(t *testing.T) {
	f, store, _, _ := runningSandboxForSnapshot(t, "sb-old-live")
	f.vsock.replyFor = func(op string) (bool, string) {
		if op == "freeze_fs" {
			return false, `unknown op \"freeze_fs\"`
		}
		return true, ""
	}
	before := len(vsockOps(t, f.vsock))
	_, err := f.driver.CreateSnapshot(context.Background(), "sb-old-live", "aerolvm-snapshot/x:latest")
	if !errors.Is(err, models.ErrSnapshotSourceNotReady) || !strings.Contains(err.Error(), "created by an older release") {
		t.Fatalf("err = %v, want the too-old 409", err)
	}
	// Nothing was frozen, so nothing to thaw.
	if ops := opsSince(t, f, before); strings.Join(ops, ",") != "freeze_fs" {
		t.Fatalf("ops = %v, want only freeze_fs", ops)
	}
	if len(store.imported) != 0 || len(exportCopies(t, f)) != 0 {
		t.Fatal("an image or a copy was made")
	}
}

func TestCreateSnapshotOfARunningSandboxFailures(t *testing.T) {
	t.Run("freeze refused", func(t *testing.T) {
		f, _, _, _ := runningSandboxForSnapshot(t, "sb-busy")
		f.vsock.replyFor = func(op string) (bool, string) {
			if op == "freeze_fs" {
				return false, "freeze root filesystem: EBUSY"
			}
			return true, ""
		}
		before := len(vsockOps(t, f.vsock))
		_, err := f.driver.CreateSnapshot(context.Background(), "sb-busy", "r:1")
		if err == nil || !strings.Contains(err.Error(), "freeze the guest's filesystem") || errors.Is(err, models.ErrSnapshotSourceNotReady) {
			t.Fatalf("err = %v, want the freeze error", err)
		}
		// A freeze that landed with only its ack lost must not stay.
		if ops := opsSince(t, f, before); len(ops) < 2 || ops[1] != "thaw_fs" {
			t.Fatalf("ops = %v, want a thaw after the failed freeze", ops)
		}
	})
	t.Run("the copy fails", func(t *testing.T) {
		f, _, _, live := runningSandboxForSnapshot(t, "sb-nocopy")
		if err := os.Remove(live); err != nil {
			t.Fatal(err)
		}
		before := len(vsockOps(t, f.vsock))
		_, err := f.driver.CreateSnapshot(context.Background(), "sb-nocopy", "r:1")
		if err == nil || !strings.Contains(err.Error(), "copy running disk") {
			t.Fatalf("err = %v, want the copy error", err)
		}
		if ops := opsSince(t, f, before); strings.Join(ops, ",") != "freeze_fs,thaw_fs" {
			t.Fatalf("ops = %v, want the sandbox thawed after the failed copy", ops)
		}
	})
	t.Run("the copy outlives the freeze", func(t *testing.T) {
		orig := guestFreezeLimit
		t.Cleanup(func() { guestFreezeLimit = orig })
		guestFreezeLimit = guestFreezeMargin // any copy is too slow
		f, store, _, _ := runningSandboxForSnapshot(t, "sb-slow")
		_, err := f.driver.CreateSnapshot(context.Background(), "sb-slow", "r:1")
		if err == nil || !strings.Contains(err.Error(), "may have changed while it was copied") {
			t.Fatalf("err = %v, want the copy discarded", err)
		}
		if len(store.imported) != 0 {
			t.Fatal("an image was made from a copy the guest may have written to")
		}
	})
	t.Run("the thaw never lands", func(t *testing.T) {
		// The copy was made frozen, so the snapshot stands; the guest's
		// safety timer thaws it.
		f, store, _, _ := runningSandboxForSnapshot(t, "sb-nothaw")
		f.vsock.replyFor = func(op string) (bool, string) {
			if op == "thaw_fs" {
				return false, "thaw root filesystem: EIO"
			}
			return true, ""
		}
		before := len(vsockOps(t, f.vsock))
		if _, err := f.driver.CreateSnapshot(context.Background(), "sb-nothaw", "r:1"); err != nil {
			t.Fatalf("CreateSnapshot with a failing thaw: %v", err)
		}
		thaws := 0
		for _, op := range opsSince(t, f, before) {
			if op == "thaw_fs" {
				thaws++
			}
		}
		if thaws != 3 || len(store.imported) != 1 {
			t.Fatalf("%d thaw attempts, %d images; want 3 attempts and the image", thaws, len(store.imported))
		}
	})
	t.Run("no vsock CID", func(t *testing.T) {
		f, _, _, _ := runningSandboxForSnapshot(t, "sb-nocid")
		f.driver.mu.Lock()
		delete(f.driver.guestCID, "sb-nocid")
		f.driver.mu.Unlock()
		f.driver.pool = nil
		if _, err := f.driver.CreateSnapshot(context.Background(), "sb-nocid", "r:1"); err == nil || !strings.Contains(err.Error(), "no vsock CID") {
			t.Fatalf("err = %v, want the missing CID", err)
		}
	})
}

// A VM whose CID the driver did not record uses its TAP slot's, as Stop does.
func TestCreateSnapshotOfARunningSandboxFindsTheCIDInThePool(t *testing.T) {
	f, _, _, _ := runningSandboxForSnapshot(t, "sb-slotcid")
	f.driver.mu.Lock()
	delete(f.driver.guestCID, "sb-slotcid")
	f.driver.mu.Unlock()
	if _, err := f.driver.CreateSnapshot(context.Background(), "sb-slotcid", "r:1"); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	if f.vsock.lastCID < 3 {
		t.Fatalf("dialed CID %d, want the slot's", f.vsock.lastCID)
	}
}

// Stop waits while a snapshot holds the VM, so it never saves a VM whose
// filesystem is frozen; a snapshot that waited for a Stop finds no VM.
func TestStopAndARunningSnapshotTakeTurns(t *testing.T) {
	f, _, _, _ := runningSandboxForSnapshot(t, "sb-turns")
	release, err := f.driver.gate.lock(context.Background(), "sb-turns")
	if err != nil {
		t.Fatal(err)
	}
	stopped := make(chan error, 1)
	go func() { stopped <- f.driver.Stop(context.Background(), "sb-turns") }()
	select {
	case err := <-stopped:
		t.Fatalf("Stop ran while the VM was held: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	release()
	if err := <-stopped; err != nil {
		t.Fatalf("Stop after the release: %v", err)
	}

	// Now the other way round: the snapshot waits, the VM goes, the
	// snapshot reports it.
	g, _, _, _ := runningSandboxForSnapshot(t, "sb-gone")
	release, err = g.driver.gate.lock(context.Background(), "sb-gone")
	if err != nil {
		t.Fatal(err)
	}
	snapped := make(chan error, 1)
	go func() {
		_, err := g.driver.CreateSnapshot(context.Background(), "sb-gone", "r:1")
		snapped <- err
	}()
	time.Sleep(50 * time.Millisecond)
	g.driver.mu.Lock()
	delete(g.driver.vmms, "sb-gone")
	g.driver.mu.Unlock()
	release()
	if err := <-snapped; !errors.Is(err, models.ErrSnapshotSourceNotReady) || !strings.Contains(err.Error(), "stopped while the snapshot waited") {
		t.Fatalf("err = %v, want the sandbox-gone 409", err)
	}
}

func TestVMGateHonoursTheContext(t *testing.T) {
	var g vmGate
	release, err := g.lock(context.Background(), "sb")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := g.lock(ctx, "sb"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lock while held = %v, want the context's error", err)
	}
	// Another sandbox's gate is independent.
	other, err := g.lock(context.Background(), "sb-other")
	if err != nil {
		t.Fatal(err)
	}
	other()
	release()
	again, err := g.lock(context.Background(), "sb")
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	again()

	// Stop surfaces a wait that ran out.
	f, _, _, _ := runningSandboxForSnapshot(t, "sb-stopwait")
	hold, _ := f.driver.gate.lock(context.Background(), "sb-stopwait")
	defer hold()
	sctx, scancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer scancel()
	if err := f.driver.Stop(sctx, "sb-stopwait"); err == nil || !strings.Contains(err.Error(), "stop sb-stopwait") {
		t.Fatalf("Stop with an expired wait = %v", err)
	}
	// A snapshot that cannot get the VM in time fails the same way.
	if _, err := f.driver.CreateSnapshot(sctx, "sb-stopwait", "r:1"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CreateSnapshot with an expired wait = %v", err)
	}
}

// Many callers waiting on one gate get it one at a time.
func TestVMGateIsExclusive(t *testing.T) {
	var g vmGate
	var mu sync.Mutex
	inside, maxInside := 0, 0
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := g.lock(context.Background(), "sb")
			if err != nil {
				t.Error(err)
				return
			}
			mu.Lock()
			inside++
			if inside > maxInside {
				maxInside = inside
			}
			mu.Unlock()
			time.Sleep(time.Millisecond)
			mu.Lock()
			inside--
			mu.Unlock()
			release()
		}()
	}
	wg.Wait()
	if maxInside != 1 {
		t.Fatalf("%d holders at once, want 1", maxInside)
	}
}
