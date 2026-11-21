package firecracker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestMain runs the package as on the production architecture, so a test
// that checks the REST calls a VM gets sees the same calls on a laptop
// (arm64) as in CI (amd64). The arm64 branch has its own test.
func TestMain(m *testing.M) {
	hostArch = "amd64"
	os.Exit(m.Run())
}

// A cold boot hides nested virtualization: the CPU config goes after the
// machine config (a later PUT /machine-config would reset it) and before
// the boot, and the VM's record says so.
func TestColdBootHidesNestedVirt(t *testing.T) {
	f := newDriverFixture(t)
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1,
	}, "sb-nv", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	order := f.client.restOrder
	mc, cpu, start := indexOf(order, "PutMachineConfig"), indexOf(order, "PutCPUConfig"), indexOf(order, "Action:"+firecracker.ActionInstanceStart)
	if mc < 0 || cpu < 0 || start < 0 || !(mc < cpu && cpu < start) {
		t.Fatalf("REST order %v: want PutMachineConfig, then PutCPUConfig, then InstanceStart", order)
	}
	if !reflect.DeepEqual(*f.client.cpu, firecracker.HideNestedVirt()) {
		t.Fatalf("CPU config = %+v, want HideNestedVirt", *f.client.cpu)
	}
	if got := f.driver.vmNestedVirt("sb-nv"); got != firecracker.NestedVirtOff {
		t.Fatalf("VM record = %q, want off", got)
	}
}

// SB_FIRECRACKER_NESTED_VIRT=true sends no CPU config, and the VM's record
// says nested virtualization is on.
func TestColdBootAllowsNestedVirtWhenTheNodeDoes(t *testing.T) {
	f := newDriverFixture(t)
	f.driver.cfg.NestedVirt = true
	if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1,
	}, "sb-nv-on", "tok", nil); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if f.client.cpu != nil {
		t.Fatalf("a node that allows nested virtualization sent a CPU config: %+v", *f.client.cpu)
	}
	if got := f.driver.vmNestedVirt("sb-nv-on"); got != firecracker.NestedVirtOn {
		t.Fatalf("VM record = %q, want on", got)
	}
}

// arm64 guests get no EL2 from Firecracker, so there is nothing to hide
// and no CPUID to change.
func TestConfigureGuestCPUOnArm64SendsNothing(t *testing.T) {
	hostArch = "arm64"
	t.Cleanup(func() { hostArch = "amd64" })
	d := New(Config{}, nil)
	client := newFakeClient()
	if err := d.configureGuestCPU(context.Background(), client); err != nil || client.cpu != nil {
		t.Fatalf("arm64: err=%v cpu=%v, want no call", err, client.cpu)
	}
}

// Firecracker refusing the CPU config fails the boot with the setting that
// avoids it named, and the VM is torn down.
func TestColdBootFailsWhenTheCPUConfigIsRefused(t *testing.T) {
	f := newDriverFixture(t)
	f.client.cpuErr = errors.New("400 Bad Request: Template changes a CPUID entry not supported by KVM")
	_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1,
	}, "sb-nv-refused", "tok", nil)
	if err == nil || !strings.Contains(err.Error(), "SB_FIRECRACKER_NESTED_VIRT") {
		t.Fatalf("Create = %v, want an error naming SB_FIRECRACKER_NESTED_VIRT", err)
	}
	if indexOf(f.client.restOrder, "Action:"+firecracker.ActionInstanceStart) >= 0 {
		t.Fatal("the VM booted after its CPU config was refused")
	}
	if !f.vmm.cleaned {
		t.Fatal("the VM was not torn down")
	}
}

// templateFixture is a driver with a template whose snapshot was saved
// under the given record, and a health notifier.
func templateFixture(t *testing.T, saved firecracker.NestedVirt) (*driverFixture, *recordingHealthNotifier) {
	t.Helper()
	f := newDriverFixture(t)
	dir := t.TempDir()
	rootfs := filepath.Join(dir, "rootfs.ext4")
	for name, body := range map[string]string{"rootfs.ext4": "ROOTFS", "snapshot.memory": "MEM", "snapshot.state": "STATE"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	f.driver.SetTemplateResolver(&fakeTemplateResolver{
		rootfsPath: rootfs, hasSnapshot: true, hasOverlay: true,
		snapshotMemoryPath: filepath.Join(dir, "snapshot.memory"), snapshotStatePath: filepath.Join(dir, "snapshot.state"),
		snapshotVsockCID: 200, snapshotNestedVirt: saved, snapshotNestedVirtSet: true,
	})
	notifier := &recordingHealthNotifier{}
	f.driver.SetTemplateHealthNotifier(notifier)
	return f, notifier
}

// A template saved under the other setting still loads: cold-booting it
// would stage the template's shared rootfs as the clone's writable disk.
// The clone inherits the template's record (so its stop snapshot says what
// CPU it has), the driver asks for nothing (the service saves such
// templates again at start), and the template is logged once.
func TestTemplateSavedUnderAnotherSettingStillLoads(t *testing.T) {
	for _, tc := range []struct {
		name        string
		saved       firecracker.NestedVirt
		nodeAllowed bool
	}{
		{"saved before the record, node hides", firecracker.NestedVirtUnknown, false},
		{"saved on, node hides", firecracker.NestedVirtOn, false},
		{"saved off, node allows", firecracker.NestedVirtOff, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, notifier := templateFixture(t, tc.saved)
			f.driver.cfg.NestedVirt = tc.nodeAllowed
			if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
				Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1, TemplateID: "tpl-nv",
			}, "sb-tpl-nv", "tok", nil); err != nil {
				t.Fatalf("Create: %v", err)
			}
			if f.client.snapshotLoad == nil || f.client.cpu != nil {
				t.Fatalf("loaded=%v cpu config=%v; want the snapshot loaded and no CPU config", f.client.snapshotLoad != nil, f.client.cpu)
			}
			if got := f.driver.vmNestedVirt("sb-tpl-nv"); got != tc.saved {
				t.Fatalf("clone record = %q, want the template's %q", got, tc.saved)
			}
			if _, logged := f.driver.staleTemplates.Load("tpl-nv"); !logged {
				t.Fatal("the stale template was not logged")
			}
			if calls := notifier.snapshot(); len(calls) != 0 {
				t.Fatalf("the driver marked the template: %+v", calls)
			}
		})
	}
}

// A template saved under this node's setting loads quietly, and its clone
// has its record. On a node that allows nested virtualization, a snapshot
// saved before the record booted with it visible, so it matches too.
func TestTemplateSnapshotSavedUnderThisSettingLoads(t *testing.T) {
	for _, tc := range []struct {
		saved       firecracker.NestedVirt
		nodeAllowed bool
	}{
		{firecracker.NestedVirtOff, false},
		{firecracker.NestedVirtOn, true},
		{firecracker.NestedVirtUnknown, true},
	} {
		f, _ := templateFixture(t, tc.saved)
		f.driver.cfg.NestedVirt = tc.nodeAllowed
		if _, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{
			Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1, TemplateID: "tpl-nv",
		}, "sb-tpl-ok", "tok", nil); err != nil {
			t.Fatalf("saved %q, node allows %v: Create: %v", tc.saved, tc.nodeAllowed, err)
		}
		_, logged := f.driver.staleTemplates.Load("tpl-nv")
		if f.client.snapshotLoad == nil || f.client.cpu != nil || logged || f.driver.vmNestedVirt("sb-tpl-ok") != tc.saved {
			t.Fatalf("saved %q, node allows %v: loaded=%v cpu=%v logged=%v record=%q", tc.saved, tc.nodeAllowed,
				f.client.snapshotLoad != nil, f.client.cpu, logged, f.driver.vmNestedVirt("sb-tpl-ok"))
		}
	}
}

// On arm64 there is nothing to hide: no CPU config, no stale-template log,
// no kept-start count, and moves are never refused for it.
func TestNestedVirtOnArm64ChecksNothing(t *testing.T) {
	hostArch = "arm64"
	t.Cleanup(func() { hostArch = "amd64" })
	ctx := context.Background()

	f, _ := templateFixture(t, firecracker.NestedVirtUnknown)
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1, TemplateID: "tpl-nv",
	}, "sb-arm", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if _, logged := f.driver.staleTemplates.Load("tpl-nv"); logged || f.client.cpu != nil {
		t.Fatalf("arm64 logged a stale template (%v) or sent a CPU config (%v)", logged, f.client.cpu)
	}
	before := nestedVirtKeptStarts.Value()
	f.driver.noteKeptNestedVirt("sb-arm", firecracker.NestedVirtOn)
	if nestedVirtKeptStarts.Value() != before {
		t.Fatal("arm64 counted a kept start")
	}

	on := exportBundle(t, "sb-arm-mv", firecracker.NestedVirtOn)
	if err := newDriverFixture(t).driver.ImportSandboxSnapshot(ctx, "sb-arm-mv", bytes.NewReader(on)); err != nil {
		t.Fatalf("arm64 refused a move: %v", err)
	}
}

func rewriteManifest(t *testing.T, d *Driver, id string, change func(*sandboxSnapshotManifest)) {
	t.Helper()
	m, err := d.readSandboxSnapshotManifest(id)
	if err != nil {
		t.Fatal(err)
	}
	change(m)
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, _, _, path := d.sandboxSnapshotPaths(id)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A stop saves the VM's record, and a start restores it: a stopped sandbox
// keeps the CPU it started with. One that sees nested virtualization on a
// node that hides it is logged and counted, and keeps its record through
// the next stop.
func TestStoppedSandboxKeepsItsNestedVirt(t *testing.T) {
	ctx := context.Background()
	f := newDriverFixture(t)
	if _, err := f.driver.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1},
		"sb-keep", "tok", nil); err != nil {
		t.Fatal(err)
	}
	if err := f.driver.Stop(ctx, "sb-keep"); err != nil {
		t.Fatal(err)
	}
	m, err := f.driver.readSandboxSnapshotManifest("sb-keep")
	if err != nil || m.NestedVirt != firecracker.NestedVirtOff {
		t.Fatalf("manifest record = %+v, %v; want off", m, err)
	}
	before := nestedVirtKeptStarts.Value()
	if _, err := f.driver.StartWithIdentity(ctx, "sb-keep", "sb-keep", "tok"); err != nil {
		t.Fatal(err)
	}
	if got := f.driver.vmNestedVirt("sb-keep"); got != firecracker.NestedVirtOff || nestedVirtKeptStarts.Value() != before {
		t.Fatalf("an off VM restarted as %q, kept starts +%d", got, nestedVirtKeptStarts.Value()-before)
	}

	// A VM saved before the record existed.
	if err := f.driver.Stop(ctx, "sb-keep"); err != nil {
		t.Fatal(err)
	}
	rewriteManifest(t, f.driver, "sb-keep", func(m *sandboxSnapshotManifest) { m.NestedVirt = firecracker.NestedVirtUnknown })
	if _, err := f.driver.StartWithIdentity(ctx, "sb-keep", "sb-keep", "tok"); err != nil {
		t.Fatalf("a sandbox saved before the record does not start: %v", err)
	}
	if got := f.driver.vmNestedVirt("sb-keep"); got != firecracker.NestedVirtUnknown || nestedVirtKeptStarts.Value() != before+1 {
		t.Fatalf("a legacy VM restarted as %q, kept starts +%d; want unknown, +1", got, nestedVirtKeptStarts.Value()-before)
	}
	if err := f.driver.Stop(ctx, "sb-keep"); err != nil {
		t.Fatal(err)
	}
	if m, _ := f.driver.readSandboxSnapshotManifest("sb-keep"); m.NestedVirt != firecracker.NestedVirtUnknown {
		t.Fatalf("its next stop recorded %q; the VM still has the CPU it was saved with", m.NestedVirt)
	}

	// A node that allows nested virtualization counts nothing, not even a
	// sandbox saved with it hidden.
	f.driver.cfg.NestedVirt = true
	if _, err := f.driver.StartWithIdentity(ctx, "sb-keep", "sb-keep", "tok"); err != nil {
		t.Fatal(err)
	}
	f.driver.noteKeptNestedVirt("sb-off", firecracker.NestedVirtOff)
	if nestedVirtKeptStarts.Value() != before+1 {
		t.Fatal("a node that allows nested virtualization counted a kept start")
	}
}

// exportBundle creates, stops and exports a sandbox on a fresh node, with
// its manifest's record set to saved.
func exportBundle(t *testing.T, id string, saved firecracker.NestedVirt) []byte {
	t.Helper()
	ctx := context.Background()
	a := newDriverFixture(t)
	if _, err := a.driver.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 1, MemoryMB: 128, DiskGB: 1}, id, "tok", nil); err != nil {
		t.Fatal(err)
	}
	if err := a.driver.Stop(ctx, id); err != nil {
		t.Fatal(err)
	}
	rewriteManifest(t, a.driver, id, func(m *sandboxSnapshotManifest) { m.NestedVirt = saved })
	var bundle bytes.Buffer
	if err := a.driver.ExportSandboxSnapshot(ctx, id, &bundle); err != nil {
		t.Fatal(err)
	}
	return bundle.Bytes()
}

// A move refuses to bring a VM saved with nested virtualization on to a
// node that hides it, before anything is in place. A node that allows it
// takes it, and a VM saved before the record moves like any sandbox that
// existed then.
func TestMoveOfANestedVirtVM(t *testing.T) {
	ctx := context.Background()
	on := exportBundle(t, "sb-mv-on", firecracker.NestedVirtOn)

	b := newDriverFixture(t)
	err := b.driver.ImportSandboxSnapshot(ctx, "sb-mv-on", bytes.NewReader(on))
	if !errors.Is(err, errNestedVirtMoveRefused) {
		t.Fatalf("import to a node that hides nested virt = %v, want errNestedVirtMoveRefused", err)
	}
	if _, err := os.Stat(b.driver.sandboxSnapshotDir("sb-mv-on")); !os.IsNotExist(err) || b.pool.alloc != 0 {
		t.Fatalf("a refused import left a folder (%v) or took a slot (%d)", err, b.pool.alloc)
	}

	allows := newDriverFixture(t)
	allows.driver.cfg.NestedVirt = true
	if err := allows.driver.ImportSandboxSnapshot(ctx, "sb-mv-on", bytes.NewReader(on)); err != nil {
		t.Fatalf("import to a node that allows nested virt: %v", err)
	}

	legacy := exportBundle(t, "sb-mv-legacy", firecracker.NestedVirtUnknown)
	if err := newDriverFixture(t).driver.ImportSandboxSnapshot(ctx, "sb-mv-legacy", bytes.NewReader(legacy)); err != nil {
		t.Fatalf("a sandbox saved before the record does not move: %v", err)
	}
}

// A restarted sandboxd takes each VM's record from the VM record, so the
// VM's next stop saves the right one; a record from a release before it
// reads unknown.
func TestAdoptedVMKeepsItsNestedVirt(t *testing.T) {
	host := stubVMMHost(t)
	d, _, _ := adoptDriver(t)
	for id, pid := range map[string]int{"sb-rec-on": 101, "sb-rec-old": 102} {
		host.procs[pid] = newFakeProcess(syscall.SIGKILL)
		rec := vmmRecord{SandboxID: id, PID: pid, StartTicks: uint64(pid) * 10, BootID: "boot-1",
			APISocket: "/sock/" + id, RunDir: filepath.Join(d.cfg.RunDir, id), VsockCID: uint32(pid), OwnsRunDir: true}
		if id == "sb-rec-on" {
			rec.NestedVirt = firecracker.NestedVirtOn
		}
		writeRecord(t, d, rec)
	}
	host.cgroup = []int{101, 102}
	if n := d.AdoptRunningVMs(context.Background(), func(context.Context, string) (bool, error) { return true, nil }); n != 2 {
		t.Fatalf("adopted %d VMs, want 2", n)
	}
	if got := d.vmNestedVirt("sb-rec-on"); got != firecracker.NestedVirtOn {
		t.Fatalf("adopted record = %q, want on", got)
	}
	if got := d.vmNestedVirt("sb-rec-old"); got != firecracker.NestedVirtUnknown {
		t.Fatalf("a VM recorded by an older release = %q, want unknown", got)
	}
}

func TestNestedVirtLabel(t *testing.T) {
	if got := nestedVirtLabel(firecracker.NestedVirtUnknown); !strings.Contains(got, "unknown") {
		t.Fatalf("label of an unknown record = %q", got)
	}
	if got := nestedVirtLabel(firecracker.NestedVirtOn); got != "on" {
		t.Fatalf("label of on = %q", got)
	}
	d := New(Config{}, nil)
	d.noteStaleTemplate(nil)
	d.noteStaleTemplate(&TemplateResolution{TemplateID: "tpl-cold", HasSnapshot: false})
	if _, logged := d.staleTemplates.Load("tpl-cold"); logged {
		t.Fatal("a template with no snapshot was logged as stale")
	}
	stale := &TemplateResolution{TemplateID: "tpl-twice", HasSnapshot: true}
	d.noteStaleTemplate(stale)
	d.noteStaleTemplate(stale)
	if _, logged := d.staleTemplates.Load("tpl-twice"); !logged {
		t.Fatal("a stale template was not logged")
	}
}
