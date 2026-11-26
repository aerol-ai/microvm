package firecracker

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/firecracker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// budgetFor is a budget for a host of hostVcpus with the device reporting
// poolMiB and slotsTotal (0: not reported) and no current slot count, so
// nothing is grown.
func budgetFor(hostVcpus, poolMiB, slotsTotal int) *nitroBudget {
	b := newNitroBudget(hostVcpus, nil)
	b.readLimits = func() (int, int) { return poolMiB, slotsTotal }
	b.readSlots = func() int { return 0 }
	b.writeSlots = func(int) error { return errors.New("not grown in this test") }
	return b
}

func refusedBy(t *testing.T, err error, pool string) {
	t.Helper()
	got, ok := capacity.SlotPoolExhausted(err)
	if !ok || got != pool || !errors.Is(err, capacity.ErrCapacityExceeded) {
		t.Fatalf("err = %v, want a capacity refusal by %q", err, pool)
	}
}

// Each limit refuses the boot that would pass it, as a capacity refusal
// naming the limit (never the node's numbers); a release makes room; a
// limit the device does not report is not checked.
func TestNitroBudgetLimits(t *testing.T) {
	t.Run("vCPUs: 5 per host vCPU", func(t *testing.T) {
		b := budgetFor(2, 0, 0) // 10 sandbox vCPUs
		for i, id := range []string{"a", "b", "c", "d"} {
			if err := b.reserve(id, 2, 256); err != nil {
				t.Fatalf("reserve %d: %v", i, err)
			}
		}
		err := b.reserve("e", 4, 256)
		refusedBy(t, err, nitroVcpuPool)
		if strings.Contains(err.Error(), "10") || strings.Contains(err.Error(), "8") {
			t.Fatalf("the refusal shows the node's numbers: %v", err)
		}
		if err := b.reserve("e", 2, 256); err != nil {
			t.Fatalf("the last two vCPUs: %v", err)
		}
		b.release("a")
		if err := b.reserve("f", 2, 256); err != nil {
			t.Fatalf("after a release: %v", err)
		}
	})
	t.Run("memory pool", func(t *testing.T) {
		b := budgetFor(64, 1024, 0)
		if err := b.reserve("a", 1, nitroPoolNeed(510, 3, false)); err != nil { // 512 with its page
			t.Fatal(err)
		}
		if err := b.reserve("b", 1, 512); err != nil { // 1024: full
			t.Fatal(err)
		}
		refusedBy(t, b.reserve("c", 1, 258), nitroMemPool)
	})
	t.Run("PCIe slots: one per running VM", func(t *testing.T) {
		b := budgetFor(64, 0, 2)
		_ = b.reserve("a", 1, 64)
		_ = b.reserve("b", 1, 64)
		refusedBy(t, b.reserve("c", 1, 64), nitroSlotsPool)
	})
	t.Run("a second reserve for one sandbox holds nothing more", func(t *testing.T) {
		b := budgetFor(1, 0, 0) // 5
		_ = b.reserve("a", 5, 64)
		if err := b.reserve("a", 5, 64); err != nil {
			t.Fatalf("a retry was refused: %v", err)
		}
		if h, ok := b.holding("a"); !ok || h.vcpus != 5 {
			t.Fatalf("holding = %+v, %v", h, ok)
		}
	})
	t.Run("an adopted VM counts whatever the limits", func(t *testing.T) {
		b := budgetFor(1, 0, 0)
		b.adopt("big", nitroHold{vcpus: 8, memMiB: 4096})
		b.adopt("none", nitroHold{}) // a record without a share: nothing
		refusedBy(t, b.reserve("a", 1, 64), nitroVcpuPool)
		if p := b.slotPool(); p.Total != 5 || p.Free != 0 || p.Name != capacity.SlotPoolNitroVcpus || p.Runtimes[0] != models.RuntimeFirecrackerNitro {
			t.Fatalf("slot pool = %+v", p)
		}
		if _, ok := b.holding("none"); ok {
			t.Fatal("an empty share was adopted")
		}
	})
	t.Run("nil budget (KVM) refuses nothing", func(t *testing.T) {
		var b *nitroBudget
		if err := b.reserve("a", 99, 99); err != nil {
			t.Fatal(err)
		}
		b.release("a")
		b.adopt("a", nitroHold{vcpus: 1})
		if _, ok := b.holding("a"); ok {
			t.Fatal("nil budget holds")
		}
	})
}

// The device's limits come from sysfs: the pool in bytes, the slots as a
// count; a file that is not there or not a number is "not reported".
func TestReadNitroDevice(t *testing.T) {
	dir := t.TempDir()
	old := nitroSysfsDir
	nitroSysfsDir = dir
	t.Cleanup(func() { nitroSysfsDir = old })
	if pool, slots := readNitroDevice(); pool != 0 || slots != 0 {
		t.Fatalf("no device: %d, %d", pool, slots)
	}
	if err := writeNitroSlots(12); err == nil {
		t.Fatal("grew slots on a machine with no device")
	}
	if err := os.MkdirAll(filepath.Join(dir, "mem_pool"), 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(dir, "mem_pool", "total"), []byte("6442450944\n"), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "pcie_slots_total"), []byte("20\n"), 0o644)
	if pool, slots := readNitroDevice(); pool != 6144 || slots != 20 {
		t.Fatalf("SP-B's machine: pool %d MiB, %d slots; want 6144, 20", pool, slots)
	}
	_ = os.WriteFile(filepath.Join(dir, "pcie_slots_total"), []byte("many\n"), 0o644)
	if _, slots := readNitroDevice(); slots != 0 {
		t.Fatalf("a bad number read as %d", slots)
	}
	_ = os.WriteFile(filepath.Join(dir, "pcie_slots"), []byte("4\n"), 0o644)
	if err := writeNitroSlots(5); err != nil {
		t.Fatal(err)
	}
	if got := readNitroSysfs("pcie_slots"); got != 5 { // a plain file keeps the write; the driver rounds it up
		t.Fatalf("pcie_slots = %d after writing 5", got)
	}
}

// fakeSlots is the Nitro driver's pcie_slots: 4 at boot, grown in steps of
// 8 up to total by a write, each step from the pool; fail is the next
// write's error.
type fakeSlots struct {
	cur, total int
	writes     []int
	fail       error
}

func (f *fakeSlots) budget(hostVcpus, poolMiB int) *nitroBudget {
	b := newNitroBudget(hostVcpus, nil)
	b.readLimits = func() (int, int) { return poolMiB, f.total }
	b.readSlots = func() int { return f.cur }
	b.writeSlots = func(target int) error {
		f.writes = append(f.writes, target)
		if f.fail != nil {
			return f.fail
		}
		for f.cur < target && f.cur < f.total {
			f.cur += nitroSlotStep
		}
		return nil
	}
	return b
}

// A machine starts with 4 PCIe slots (live run m2-nitro-adm-1126 stopped
// there): the 5th VM grows them a step first, and the step's 128 MiB of
// the pool is counted; a step the pool cannot give, or one past the
// total, is a capacity refusal; a write that fails otherwise too.
func TestNitroBudgetGrowsSlots(t *testing.T) {
	t.Run("the fifth VM grows the slots a step", func(t *testing.T) {
		dev := &fakeSlots{cur: 4, total: 20}
		b := dev.budget(64, 2048)
		for i := 0; i < 4; i++ {
			if err := b.reserve(fmt.Sprint("v", i), 1, 258); err != nil {
				t.Fatal(err)
			}
		}
		if len(dev.writes) != 0 {
			t.Fatalf("grew slots with room: %v", dev.writes)
		}
		if err := b.reserve("v4", 1, 258); err != nil {
			t.Fatal(err)
		}
		if len(dev.writes) != 1 || dev.writes[0] != 5 || dev.cur != 12 {
			t.Fatalf("writes %v, slots %d; want one write of 5 and 12 slots", dev.writes, dev.cur)
		}
		// 2048 MiB: 128 for the step, 7 VMs of 258 = 1806; the 8th needs 258 more.
		for i := 5; i < 7; i++ {
			if err := b.reserve(fmt.Sprint("v", i), 1, 258); err != nil {
				t.Fatalf("VM %d: %v", i, err)
			}
		}
		refusedBy(t, b.reserve("v7", 1, 258), nitroMemPool)
		if len(dev.writes) != 1 {
			t.Fatalf("grew again inside the step: %v", dev.writes)
		}
	})
	t.Run("the pool cannot give the step", func(t *testing.T) {
		dev := &fakeSlots{cur: 4, total: 20, fail: syscall.ENOMEM}
		b := dev.budget(64, 8192)
		for i := 0; i < 4; i++ {
			_ = b.reserve(fmt.Sprint("v", i), 1, 258)
		}
		refusedBy(t, b.reserve("v4", 1, 258), nitroMemPool)
		if _, ok := b.holding("v4"); ok {
			t.Fatal("a refused VM is held")
		}
	})
	t.Run("a step that would not leave room for the VM is not taken", func(t *testing.T) {
		dev := &fakeSlots{cur: 4, total: 20}
		b := dev.budget(64, 4*258+128) // room for the step, not for a 5th VM
		for i := 0; i < 4; i++ {
			_ = b.reserve(fmt.Sprint("v", i), 1, 258)
		}
		refusedBy(t, b.reserve("v4", 1, 258), nitroMemPool)
		if len(dev.writes) != 0 {
			t.Fatalf("donated a step for a VM that did not fit: %v", dev.writes)
		}
	})
	t.Run("past the total", func(t *testing.T) {
		dev := &fakeSlots{cur: 4, total: 4}
		b := dev.budget(64, 8192)
		for i := 0; i < 4; i++ {
			_ = b.reserve(fmt.Sprint("v", i), 1, 258)
		}
		refusedBy(t, b.reserve("v4", 1, 258), nitroSlotsPool)
		if len(dev.writes) != 0 {
			t.Fatalf("tried to grow past the total: %v", dev.writes)
		}
	})
	t.Run("a read-only sysfs", func(t *testing.T) {
		dev := &fakeSlots{cur: 4, total: 20, fail: syscall.EROFS}
		b := dev.budget(64, 8192)
		for i := 0; i < 4; i++ {
			_ = b.reserve(fmt.Sprint("v", i), 1, 258)
		}
		refusedBy(t, b.reserve("v4", 1, 258), nitroSlotsPool)
	})
}

// A VM's pool need: its memory and control page, and in confidential mode
// a 16 MiB buffer per device.
func TestNitroPoolNeed(t *testing.T) {
	if got := nitroPoolNeed(512, 3, false); got != 514 {
		t.Fatalf("direct: %d", got)
	}
	if got := nitroPoolNeed(512, 4, true); got != 514+64 {
		t.Fatalf("confidential with an overlay: %d", got)
	}
	d := New(Config{Backend: "nitro", NitroMode: "confidential"}, nil)
	if got := d.nitroNeed(256, false); got != 258+48 {
		t.Fatalf("nitroNeed = %d", got)
	}
	if slotStepsMiB(4) != 0 || slotStepsMiB(5) != 128 || slotStepsMiB(12) != 128 || slotStepsMiB(20) != 256 {
		t.Fatal("slot steps")
	}
}

// nitroFixture is a Nitro driver fixture whose budget is a host of
// hostVcpus with no other device limits.
func nitroFixture(t *testing.T, hostVcpus int) *driverFixture {
	f := newDriverFixture(t)
	f.driver.cfg.Backend = "nitro"
	f.driver.budget = budgetFor(hostVcpus, 0, 0)
	return f
}

// A create past the budget is refused before it takes a slot or builds a
// disk; a create that fails gives its share back; a destroy frees it.
func TestCreate_NitroBudget(t *testing.T) {
	f := nitroFixture(t, 1) // 5 sandbox vCPUs
	ctx := context.Background()
	create := func(id string, cpu float64) error {
		_, err := f.driver.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeFirecrackerNitro, CPU: cpu, MemoryMB: 256}, id, "tok", nil)
		return err
	}
	if err := create("sb-4", 4); err != nil {
		t.Fatalf("4 vCPUs: %v", err)
	}
	allocs, builds := f.pool.alloc, f.rootfs.builds
	refusedBy(t, create("sb-2", 2), nitroVcpuPool)
	if f.pool.alloc != allocs || f.rootfs.builds != builds {
		t.Fatal("a refused create did work")
	}
	f.client.enclaveErr = errors.New("400")
	if err := create("sb-1", 1); err == nil {
		t.Fatal("the enclave failure was lost")
	}
	if _, ok := f.driver.budget.holding("sb-1"); ok {
		t.Fatal("a failed create kept its share")
	}
	f.client.enclaveErr = nil
	if err := f.driver.Destroy(ctx, &models.Sandbox{ID: "sb-4", Runtime: models.RuntimeFirecrackerNitro}); err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if err := create("sb-5", 5); err != nil {
		t.Fatalf("after the destroy: %v", err)
	}
}

// A Nitro VM's share is held while it runs: Stop gives it back (its
// enclave ends), Start takes it again, and a start with no room is refused
// before any work, keeping the sandbox stopped and its disk.
func TestNitroStopStartBudget(t *testing.T) {
	f := nitroFixture(t, 1)
	nitroStopped(t, f, "sb-a") // 2 vCPUs
	if _, ok := f.driver.budget.holding("sb-a"); ok {
		t.Fatal("a stopped VM still holds its share")
	}
	if err := f.driver.budget.reserve("other", 4, 64); err != nil {
		t.Fatal(err)
	}
	starts := f.vmm.started
	f.vmm.started = false
	_, err := f.driver.StartWithIdentityEnv(context.Background(), "sb-a", "sb-a", "tok", func(context.Context) (map[string]string, error) { return nil, nil })
	refusedBy(t, err, nitroVcpuPool)
	if f.vmm.started {
		t.Fatal("a refused start began a VM")
	}
	if _, err := f.driver.readSandboxSnapshotManifest("sb-a"); err != nil {
		t.Fatalf("a refused start lost the kept disk: %v", err)
	}
	f.vmm.started = starts
	f.driver.budget.release("other")
	if _, err := f.driver.StartWithIdentityEnv(context.Background(), "sb-a", "sb-a", "tok", func(context.Context) (map[string]string, error) { return nil, nil }); err != nil {
		t.Fatalf("start with room: %v", err)
	}
	if h, ok := f.driver.budget.holding("sb-a"); !ok || h.vcpus != 2 || h.memMiB != 770 {
		t.Fatalf("started VM holds %+v, %v; want its saved shape", h, ok)
	}
}

// Firecracker refuses odd or tiny memory on Nitro at InstanceStart; the
// driver says so before any work.
func TestCreate_NitroMemoryShape(t *testing.T) {
	for _, mem := range []int{0, 254, 513} {
		f := nitroFixture(t, 8)
		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeFirecrackerNitro, MemoryMB: mem}, "sb-m", "tok", nil)
		if err == nil || !strings.Contains(err.Error(), "needs memory_mb to be an even number, at least 256") {
			t.Fatalf("memory %d: err = %v", mem, err)
		}
		if f.pool.alloc != 0 {
			t.Fatalf("memory %d: a refused create took a slot", mem)
		}
	}
	for _, mem := range []int{256, 512} {
		if err := checkNitroShape(mem); err != nil {
			t.Fatalf("memory %d refused: %v", mem, err)
		}
	}
}

// The VM's record carries its share, and a restarted sandboxd takes it
// back with the VM, so the budget still counts VMs it did not boot.
func TestNitroShareSurvivesARestart(t *testing.T) {
	host := stubVMMHost(t)
	d, _, _ := adoptDriver(t)
	d.cfg.Backend = "nitro"
	d.budget = budgetFor(1, 0, 0)
	if err := d.budget.reserve("sb-n", 3, 512); err != nil {
		t.Fatal(err)
	}
	handle := &fakeVMM{pid: 777, apiSocket: "/sock/sb-n", runDir: filepath.Join(d.cfg.RunDir, "sb-n")}
	d.register("sb-n", newFakeClient(), handle, 9, true, firecracker.NestedVirtOff)
	rec, ok := readRecord(t, d, "sb-n")
	if !ok || rec.NitroVcpus != 3 || rec.NitroMemMiB != 512 {
		t.Fatalf("record = %+v (present %v), want the share", rec, ok)
	}

	// A new sandboxd: an empty budget, the same record, the VM still up.
	d2, _, _ := adoptDriver(t)
	d2.cfg = d.cfg
	d2.budget = budgetFor(1, 0, 0)
	host.procs[777] = newFakeProcess(syscall.SIGKILL)
	writeRecord(t, d2, rec)
	if n := d2.AdoptRunningVMs(context.Background(), func(context.Context, string) (bool, error) { return true, nil }); n != 1 {
		t.Fatalf("adopted %d VMs, want 1", n)
	}
	if h, ok := d2.budget.holding("sb-n"); !ok || h.vcpus != 3 || h.memMiB != 512 {
		t.Fatalf("adopted share = %+v, %v", h, ok)
	}
	refusedBy(t, d2.budget.reserve("sb-x", 3, 64), nitroVcpuPool)
}

// The driver reports its vCPU budget as a slot pool on a Nitro node only.
func TestNitroSlotPool(t *testing.T) {
	kvm := newDriverFixture(t)
	if _, ok := kvm.driver.NitroSlotPool(); ok {
		t.Fatal("a KVM node reported a Nitro pool")
	}
	d := New(Config{Backend: "nitro"}, nil)
	pool, ok := d.NitroSlotPool()
	if !ok || pool.Total < nitroVcpusPerHostVcpu || pool.Free != pool.Total {
		t.Fatalf("pool = %+v, %v", pool, ok)
	}
}

// The Nitro System can refuse a VM for want of resources the budget cannot
// see (live run m2-nitro-adm-1126: the 5th VM after ten deleted ones). The
// refusal reaches the caller as a capacity refusal naming no internals,
// on a create and on a start; the same error on KVM, or any other start
// error, is left as it is.
func TestNitroOutOfResourcesIsACapacityRefusal(t *testing.T) {
	// Firecracker's words from that run.
	enospc := errors.New(`firecracker: PUT /actions -> 400: {"fault_message":"Start microvm error: Enclave builder error: Enclave VM error: Failed to create enclave VM: No space left on device (os error 28)"}`)
	t.Run("create", func(t *testing.T) {
		f := nitroFixture(t, 8)
		f.client.actionErr = enospc
		_, err := f.driver.Create(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20", Runtime: models.RuntimeFirecrackerNitro, MemoryMB: 256}, "sb-full", "tok", nil)
		refusedBy(t, err, nitroHostPool)
		if strings.Contains(err.Error(), "Enclave") || strings.Contains(err.Error(), "fault_message") {
			t.Fatalf("the refusal carries Firecracker's internals: %v", err)
		}
		if _, ok := f.driver.budget.holding("sb-full"); ok {
			t.Fatal("the refused create kept its share")
		}
	})
	t.Run("start", func(t *testing.T) {
		f := nitroFixture(t, 8)
		nitroStopped(t, f, "sb-s")
		f.client.actionErr = enospc
		_, err := f.driver.StartWithIdentityEnv(context.Background(), "sb-s", "sb-s", "tok", func(context.Context) (map[string]string, error) { return nil, nil })
		refusedBy(t, err, nitroHostPool)
	})
	t.Run("kvm and other errors are left alone", func(t *testing.T) {
		kvm := newDriverFixture(t)
		if kvm.driver.nitroOutOfResources("sb", enospc) != nil {
			t.Fatal("a KVM node turned an error into a Nitro refusal")
		}
		f := nitroFixture(t, 8)
		if f.driver.nitroOutOfResources("sb", errors.New("400: bad kernel")) != nil || f.driver.nitroOutOfResources("sb", nil) != nil {
			t.Fatal("a non-resource error became a capacity refusal")
		}
	})
}
