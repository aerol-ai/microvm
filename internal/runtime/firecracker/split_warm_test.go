package firecracker

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	vmmpool "github.com/aerol-ai/microvm/internal/pool/vmm"
	sbruntime "github.com/aerol-ai/microvm/internal/runtime"
	"github.com/aerol-ai/microvm/pkg/models"
)

// The warm VM pool in privilege mode split (M1 PR 18): a slot's VM runs
// under the slot's ID for its whole life, and every helper call for it,
// claimed or not, names the slot's jail.

const testSlot = "vmms-0123456789abcdef"

// splitWarmSlot fills one warm slot through WarmSpawn and hands it to a
// fake pool as the real pool would after RecordLoaded.
func splitWarmSlot(t *testing.T, f *fakeSplit, d *Driver, tpl *TemplateResolution) (*fakeWarmPool, WarmHandle) {
	t.Helper()
	h, err := d.WarmSpawn(context.Background(), WarmSpawnRequest{SlotID: testSlot, TemplateID: tpl.TemplateID, RootfsPath: tpl.RootfsPath,
		SnapshotMemoryPath: tpl.SnapshotMemoryPath, SnapshotStatePath: tpl.SnapshotStatePath, VsockCID: tpl.SnapshotVsockCID, HasOverlay: tpl.HasOverlay})
	if err != nil {
		t.Fatal(err)
	}
	pool := &fakeWarmPool{handle: h, slot: &vmmpool.Slot{ID: testSlot, TemplateID: tpl.TemplateID, Status: vmmpool.StatusAllocated,
		APISocket: h.APISocket(), RunDir: h.RunDir(), VsockCID: tpl.SnapshotVsockCID}}
	d.SetWarmPool(pool)
	return pool, h
}

// TestSplitWarmSpawn: a refill in split mode makes the slot's jail and TAP,
// runs its jailer, shares the template's three read-only files in one call,
// moves the overlay placeholder in as the jailer's, loads the snapshot by
// chroot names, and has the helper share the sockets after the load: all
// under the slot's ID, all off the create path.
func TestSplitWarmSpawn(t *testing.T) {
	f := newFakeSplit(t)
	d, client, _, _ := splitDriver(t, f)
	tpl := splitTemplate(t, 7)
	_, h := splitWarmSlot(t, f, d, tpl)
	want := []string{"snaptap fctap-test 7", "prepare " + testSlot, "spawn " + testSlot,
		"share " + testSlot + " snapshot.memory,snapshot.state,rootfs.ext4", "prepare " + testSlot + " overlay.ext4", "prepare " + testSlot}
	if got := f.seen(); !slices.Equal(got, want) {
		t.Fatalf("helper calls\n got %v\nwant %v", got, want)
	}
	load := client.snapshotLoad
	if load == nil || load.ResumeVM || load.SnapshotPath != sandboxSnapshotStateFileName || load.MemBackend.BackendPath != sandboxSnapshotMemoryFileName {
		t.Fatalf("LoadSnapshot = %+v", load)
	}
	root, stage := f.jail(testSlot)
	if h.RunDir() != root {
		t.Fatalf("the slot's run dir is %s, want its chroot %s", h.RunDir(), root)
	}
	if !sameFileAs(tpl.RootfsPath, filepath.Join(root, rootfsFileName)) || !sameFileAs(tpl.SnapshotMemoryPath, filepath.Join(root, sandboxSnapshotMemoryFileName)) {
		t.Fatal("the chroot's disk and memory are not the template's own files")
	}
	if _, err := os.Stat(filepath.Join(root, overlayFileName)); err != nil {
		t.Fatalf("the overlay placeholder is not in the chroot: %v", err)
	}
	if entries, _ := os.ReadDir(stage); len(entries) != 0 {
		t.Fatalf("the stage folder holds %v after the refill", entries)
	}
	// A refused share fails the refill and ends the slot's VM.
	f2 := newFakeSplit(t)
	d2, _, _, _ := splitDriver(t, f2)
	f2.shareErr = errors.New("refused: host")
	if _, err := d2.WarmSpawn(context.Background(), WarmSpawnRequest{SlotID: testSlot, TemplateID: "tpl-1", RootfsPath: tpl.RootfsPath,
		SnapshotMemoryPath: tpl.SnapshotMemoryPath, SnapshotStatePath: tpl.SnapshotStatePath, VsockCID: 7}); err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("a refused share: %v", err)
	}
	if got := f2.seen(); !slices.Contains(got, "stop "+testSlot) || !slices.Contains(got, "untap fctap-test") {
		t.Fatalf("a failed refill left its VM or TAP: %v", got)
	}
}

// TestSplitWarmClaim: a claim in split mode names only the slot's jail, and
// pays a helper call only for what single mode does as root on the create
// path: an overlay of the sandbox's own, or sockets the refill did not
// share.
func TestSplitWarmClaim(t *testing.T) {
	cases := []struct {
		name       string
		hasOverlay bool
		overlayGB  int
		shared     bool
		want       []string
		overlayAPI string
	}{
		{name: "no overlay", shared: true},
		{name: "the template's placeholder", hasOverlay: true, shared: true, overlayAPI: overlayFileName},
		{name: "an overlay of its own", hasOverlay: true, overlayGB: 1, shared: true,
			want: []string{"mkfs " + testSlot + " overlay.ext4", "prepare " + testSlot + " overlay.ext4"}, overlayAPI: overlayFileName},
		{name: "sockets not shared yet", shared: false, want: []string{"prepare " + testSlot}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSplit(t)
			d, client, vsock, _ := splitDriver(t, f)
			tpl := splitTemplate(t, 7)
			tpl.HasOverlay = tc.hasOverlay
			d.SetTemplateResolver(fakeResolver{res: tpl})
			pool, _ := splitWarmSlot(t, f, d, tpl)
			old := agentSocket
			t.Cleanup(func() { agentSocket = old })
			agentSocket = func(string) bool { return tc.shared }
			n := len(f.seen())
			state, err := d.Create(context.Background(), models.CreateSandboxRequest{TemplateID: "tpl-1", CPU: 1, MemoryMB: 128,
				OverlaySizeGB: tc.overlayGB}, "sb-w", "tok", nil)
			if err != nil {
				t.Fatal(err)
			}
			if got := f.seen()[n:]; !slices.Equal(got, tc.want) {
				t.Fatalf("the claim's helper calls %v, want %v", got, tc.want)
			}
			if state.ContainerIP != "172.16.0.2" || len(pool.acquireCalls) != 1 || pool.acquireCalls[0].TemplateID != "tpl-1" {
				t.Fatalf("state %+v, acquires %+v", state, pool.acquireCalls)
			}
			if got := client.drivePatches[overlayDriveID].PathOnHost; got != tc.overlayAPI {
				t.Fatalf("overlay drive patched to %q, want %q", got, tc.overlayAPI)
			}
			root, _ := f.jail(testSlot)
			if vsock.lastSocketPath != filepath.Join(root, hostVsockUDSName) {
				t.Fatalf("handshake on %s, want the slot's chroot", vsock.lastSocketPath)
			}
			// The lease cannot freeze it, as no split VM: recreate-policy
			// VMs stay off lease nodes (FenceReady), warm or cold.
			if err := d.FenceReady("sb-w"); !errors.Is(err, sbruntime.ErrCannotFreeze) {
				t.Fatalf("FenceReady of a claimed slot: %v", err)
			}
			// Destroy ends the slot's VM and jail by the slot's ID.
			n = len(f.seen())
			if err := d.Destroy(context.Background(), &models.Sandbox{ID: "sb-w"}); err != nil {
				t.Fatal(err)
			}
			if got := f.seen()[n:]; !slices.Contains(got, "stop "+testSlot) || slices.Contains(got, "stop sb-w") {
				t.Fatalf("destroy's helper calls %v, want the slot's jail stopped", got)
			}
		})
	}
}

// TestSplitWarmClaimRefusals: a slot row whose run dir is not that slot's
// own jail is refused before any helper call, and the slot is given back.
func TestSplitWarmClaimRefusals(t *testing.T) {
	for _, tc := range []struct{ name, id, runDir string }{
		{"another sandbox's jail", testSlot, "sb-other"},
		{"a slot ID with ../", "../" + testSlot, testSlot},
		{"the stage folder", testSlot, "stage"},
		{"outside the jails", testSlot, "/var/lib/elsewhere/root"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeSplit(t)
			d, _, _, _ := splitDriver(t, f)
			tpl := splitTemplate(t, 7)
			d.SetTemplateResolver(fakeResolver{res: tpl})
			pool, _ := splitWarmSlot(t, f, d, tpl)
			runDir := tc.runDir
			switch {
			case runDir == "stage":
				_, runDir = f.jail(testSlot)
			case !filepath.IsAbs(runDir):
				runDir, _ = f.jail(runDir)
			}
			pool.slot.ID, pool.slot.RunDir = tc.id, runDir
			tp := d.pool.(*fakePool)
			tp.mu.Lock()
			tp.slots[tc.id] = tp.slots[testSlot]
			tp.mu.Unlock()
			n := len(f.seen())
			if _, err := d.Create(context.Background(), models.CreateSandboxRequest{TemplateID: "tpl-1", CPU: 1, MemoryMB: 128}, "sb-w", "tok", nil); err == nil ||
				!strings.Contains(err.Error(), "not its own jail") {
				t.Fatalf("Create: %v", err)
			}
			// Only the rollback's own calls: the slot's VM ended, its TAP gone.
			for _, c := range f.seen()[n:] {
				if c != "stop "+testSlot && c != "untap fctap-test" {
					t.Fatalf("a helper call for a refused claim: %v", f.seen()[n:])
				}
			}
			if len(pool.releaseCalls) == 0 {
				t.Fatal("the refused slot was not given back")
			}
		})
	}
}

// TestSplitWarmAdoption: after a sandboxd restart, a claimed slot's VM is
// opened by the slot's jail its record names, and a cold VM by its own; a
// cold VM's jail goes through the helper on destroy, a claimed slot's is
// the pool's to reap.
func TestSplitWarmAdoption(t *testing.T) {
	f := newFakeSplit(t)
	d, _, _, _ := splitDriver(t, f)
	warmRoot, _ := f.jail(testSlot)
	coldRoot, _ := f.jail("sb-cold")
	keep := func(context.Context, string) (bool, error) { return true, nil }
	if !d.adoptVM(context.Background(), vmmRecord{SandboxID: "sb-warm", PID: 77, RunDir: warmRoot, APISocket: filepath.Join(warmRoot, jailerAPISocketName)}, keep) {
		t.Fatal("the claimed slot's VM was not adopted")
	}
	if !d.adoptVM(context.Background(), vmmRecord{SandboxID: "sb-cold", PID: 78, RunDir: coldRoot, OwnsRunDir: true}, keep) {
		t.Fatal("the cold VM was not adopted")
	}
	if got := f.seen(); !slices.Equal(got[:2], []string{"open " + testSlot, "open sb-cold"}) {
		t.Fatalf("opens %v", got)
	}
	// A record whose run dir is no jail is opened by its sandbox's ID.
	if got := d.splitRecordJail(vmmRecord{SandboxID: "sb-x", RunDir: "/elsewhere"}); got != "sb-x" {
		t.Fatalf("splitRecordJail = %s", got)
	}
	n := len(f.seen())
	for _, id := range []string{"sb-warm", "sb-cold"} {
		if err := d.Destroy(context.Background(), &models.Sandbox{ID: id}); err != nil {
			t.Fatalf("destroy %s: %v", id, err)
		}
	}
	if got := f.seen()[n:]; !slices.Contains(got, "stop sb-cold") || slices.Contains(got, "stop "+testSlot) {
		t.Fatalf("destroy's helper calls %v, want the cold VM's jail stopped and the slot's left to the reap", got)
	}
}

// TestSplitWarmOrphanReap: a released slot a restart left goes through the
// helper by the slot's ID, and only when its row names the slot's own jail.
func TestSplitWarmOrphanReap(t *testing.T) {
	f := newFakeSplit(t)
	d, _, _, _ := splitDriver(t, f)
	old := warmSocketAnswers
	t.Cleanup(func() { warmSocketAnswers = old })
	warmSocketAnswers = func(string) (bool, error) { return false, nil }
	root, _ := f.jail(testSlot)
	other, _ := f.jail("sb-other")
	if err := d.cleanupOrphanWarmSlot(context.Background(), vmmpool.Slot{ID: testSlot, RunDir: other, APISocket: filepath.Join(other, "api.socket")}); err == nil {
		t.Fatal("a slot row naming another VM's jail")
	}
	if slices.Contains(f.seen(), "stop sb-other") || slices.Contains(f.seen(), "stop "+testSlot) {
		t.Fatalf("a refused reap reached the helper: %v", f.seen())
	}
	if err := d.cleanupOrphanWarmSlot(context.Background(), vmmpool.Slot{ID: testSlot, RunDir: root, APISocket: filepath.Join(root, "api.socket")}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.seen(), "stop "+testSlot) {
		t.Fatalf("the slot's jail was not stopped: %v", f.seen())
	}
	// A VM still answering on the slot's socket waits.
	warmSocketAnswers = func(string) (bool, error) { return true, nil }
	if err := d.cleanupOrphanWarmSlot(context.Background(), vmmpool.Slot{ID: testSlot, RunDir: root, APISocket: filepath.Join(root, "api.socket")}); err == nil {
		t.Fatal("reaped a slot whose VM still answers")
	}
}

// TestSplitLeaseCannotFreeze: the lease cannot freeze a split VM; Thaw is
// a no-op.
func TestSplitLeaseCannotFreeze(t *testing.T) {
	d, _, _, _ := splitDriver(t, newFakeSplit(t))
	if err := d.Freeze(context.Background(), "sb-1"); !errors.Is(err, sbruntime.ErrCannotFreeze) {
		t.Fatalf("Freeze: %v", err)
	}
	if err := d.Thaw(context.Background(), "sb-1"); err != nil {
		t.Fatalf("Thaw: %v", err)
	}
}

// TestAgentSocket: a socket is sandboxd's to dial only when its group is
// one of sandboxd's and the group may read and write it.
func TestAgentSocket(t *testing.T) {
	dir, err := os.MkdirTemp("/tmp", "fcsock")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	if agentSocket(filepath.Join(dir, "none")) {
		t.Fatal("a missing socket")
	}
	plain := filepath.Join(dir, "plain")
	if err := os.WriteFile(plain, nil, 0o660); err != nil {
		t.Fatal(err)
	}
	if agentSocket(plain) {
		t.Fatal("a file that is no socket")
	}
	sock := filepath.Join(dir, "v.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// A new file takes its folder's group on some systems: the helper
	// gives the socket sandboxd's group, as this does.
	if err := os.Chown(sock, -1, os.Getegid()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sock, 0o600); err != nil {
		t.Fatal(err)
	}
	if agentSocket(sock) {
		t.Fatal("a socket its group cannot use")
	}
	if err := os.Chmod(sock, 0o660); err != nil {
		t.Fatal(err)
	}
	if !agentSocket(sock) {
		t.Fatal("sandboxd's own group's socket, 0660")
	}
}
