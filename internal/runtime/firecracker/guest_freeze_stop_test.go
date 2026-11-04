package firecracker

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// Stop has the guest flush and freeze its root filesystem before the pause,
// so the saved rootfs.ext4 holds every write made before Stop: a flush alone
// lets the guest's programs keep writing until the pause. CreateSnapshot
// exports that disk alone, so it needs the freeze; Start restores memory,
// which holds the freeze too, and lifts it.

func stoppedFixtureSandbox(t *testing.T, id string) *driverFixture {
	t.Helper()
	f := newDriverFixture(t)
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128,
	}, id, "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	return f
}

// vsockOps lists the ops the driver sent, in order.
func vsockOps(t *testing.T, d *fakeVsockDialer) []string {
	t.Helper()
	var ops []string
	for _, w := range d.snapshotWrites() {
		var msg struct {
			Op string `json:"op"`
		}
		if err := json.Unmarshal(w, &msg); err == nil && msg.Op != "" {
			ops = append(ops, msg.Op)
		}
	}
	return ops
}

func indexOf(ops []string, op string) int {
	for i, o := range ops {
		if o == op {
			return i
		}
	}
	return -1
}

func TestStopFreezesTheGuestBeforeThePause(t *testing.T) {
	f := stoppedFixtureSandbox(t, "sb-freeze-ok")
	before := len(vsockOps(t, f.vsock))
	if err := f.driver.Stop(context.Background(), "sb-freeze-ok"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	ops := vsockOps(t, f.vsock)[before:]
	// Session recordings are written before the freeze holds the disk
	// still; the VM is saved frozen, so nothing thaws it here.
	if !slices.Equal(ops, []string{"pre_snapshot", "freeze_fs"}) {
		t.Fatalf("ops sent by Stop = %v, want [pre_snapshot freeze_fs]", ops)
	}
	manifest, err := f.driver.readSandboxSnapshotManifest("sb-freeze-ok")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.GuestFlush != guestFlushDone {
		t.Fatalf("manifest.GuestFlush = %q after the guest acked freeze_fs, want done", manifest.GuestFlush)
	}
}

// An agent from before freeze_fs answers "unknown op". Stop still saves the
// VM (Start does not need the freeze), and records that this agent cannot
// freeze, which no later Stop will change.
func TestStopRecordsAnUnfrozenDiskWhenTheGuestCannotFreeze(t *testing.T) {
	f := stoppedFixtureSandbox(t, "sb-freeze-old")
	f.vsock.mu.Lock()
	f.vsock.guestRespOk, f.vsock.guestError = false, `unknown op \"freeze_fs\"`
	f.vsock.mu.Unlock()
	before := len(vsockOps(t, f.vsock))
	if err := f.driver.Stop(context.Background(), "sb-freeze-old"); err != nil {
		t.Fatalf("Stop with an agent that cannot freeze: %v", err)
	}
	manifest, err := f.driver.readSandboxSnapshotManifest("sb-freeze-old")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.GuestFlush != guestFlushUnsupported {
		t.Fatalf("manifest.GuestFlush = %q for an agent without freeze_fs, want unsupported", manifest.GuestFlush)
	}
	if indexOf(vsockOps(t, f.vsock)[before:], "thaw_fs") >= 0 {
		t.Fatal("thawed a guest that cannot have frozen")
	}
}

// A freeze that fails (or whose ack is lost) is thawed, in case it landed,
// and the saved disk is recorded as not flushed.
func TestStopRecordsAFailedFreeze(t *testing.T) {
	f := stoppedFixtureSandbox(t, "sb-freeze-fail")
	f.vsock.mu.Lock()
	f.vsock.replyFor = func(op string) (bool, string) {
		if op == "freeze_fs" {
			return false, "freeze root filesystem: device busy"
		}
		return true, ""
	}
	f.vsock.mu.Unlock()
	before := len(vsockOps(t, f.vsock))
	if err := f.driver.Stop(context.Background(), "sb-freeze-fail"); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if ops := vsockOps(t, f.vsock)[before:]; !slices.Equal(ops, []string{"pre_snapshot", "freeze_fs", "thaw_fs"}) {
		t.Fatalf("ops = %v, want the failed freeze thawed", ops)
	}
	manifest, err := f.driver.readSandboxSnapshotManifest("sb-freeze-fail")
	if err != nil {
		t.Fatal(err)
	}
	if manifest.GuestFlush != guestFlushFailed {
		t.Fatalf("manifest.GuestFlush = %q, want failed", manifest.GuestFlush)
	}
}

// A Stop that fails after the freeze hands the sandbox back running, so it
// must hand it back able to write: resumed and thawed.
func TestAFailedStopThawsTheGuest(t *testing.T) {
	for _, tc := range []struct {
		name   string
		break_ func(c *fakeClient)
	}{
		{"the pause fails", func(c *fakeClient) { c.patchVMErr = errors.New("pause refused") }},
		{"saving the VM fails", func(c *fakeClient) { c.snapshotCreateErr = errors.New("disk full") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := "sb-stop-" + strings.ReplaceAll(tc.name, " ", "-")
			f := stoppedFixtureSandbox(t, id)
			tc.break_(f.client)
			before := len(vsockOps(t, f.vsock))
			if err := f.driver.Stop(context.Background(), id); err == nil {
				t.Fatal("Stop succeeded")
			}
			if ops := vsockOps(t, f.vsock)[before:]; !slices.Equal(ops, []string{"pre_snapshot", "freeze_fs", "thaw_fs"}) {
				t.Fatalf("ops = %v, want the freeze thawed", ops)
			}
		})
	}
}

// Start thaws only a VM Stop froze: one whose agent could not freeze has
// nothing to thaw.
func TestStartThawsOnlyAFrozenStop(t *testing.T) {
	f, _, _, _ := envFixture(t)
	ctx := context.Background()
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", MemoryMB: 128}, "sb-unfrozen", tokenCanary, nil); err != nil {
		t.Fatal(err)
	}
	old := newOpVsockDialer()
	old.reply = func(op string, _ int) string {
		if op == "freeze_fs" {
			return `unknown op "freeze_fs"`
		}
		return ""
	}
	f.driver.SetVsockDialer(old)
	if err := f.driver.Stop(ctx, "sb-unfrozen"); err != nil {
		t.Fatal(err)
	}
	vsock := newOpVsockDialer()
	f.driver.SetVsockDialer(vsock)
	f.vmm.shutdown = false
	if _, err := f.driver.StartWithIdentity(ctx, "sb-unfrozen", "sb-unfrozen", tokenCanary); err != nil {
		t.Fatal(err)
	}
	if got := vsock.opList(); !slices.Equal(got, []string{"ping", "post_resume", guestAdoptOp}) {
		t.Fatalf("restore ops = %v, want no thaw_fs", got)
	}
}

// An adopted VM is thawed: the sandboxd that died may have frozen it.
func TestAdoptRunningVMsThawsEachVM(t *testing.T) {
	host := stubVMMHost(t)
	d, _, _ := adoptDriver(t)
	vsock := newOpVsockDialer()
	d.SetVsockDialer(vsock)
	host.procs[101] = newFakeProcess()
	writeRecord(t, d, vmmRecord{SandboxID: "sb-a", PID: 101, StartTicks: 1010, BootID: "boot-1",
		APISocket: "/sock", RunDir: "/run/sb-a", VsockCID: 7})
	if n := d.AdoptRunningVMs(context.Background(), func(context.Context, string) (bool, error) { return true, nil }); n != 1 {
		t.Fatalf("adopted %d", n)
	}
	deadline := time.Now().Add(5 * time.Second)
	for !slices.Contains(vsock.opList(), "thaw_fs") {
		if time.Now().After(deadline) {
			t.Fatalf("no thaw_fs sent; ops %v", vsock.opList())
		}
		time.Sleep(10 * time.Millisecond)
	}
}
