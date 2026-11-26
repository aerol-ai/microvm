package firecracker

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Admission on the Nitro backend (plans/security-gaps-m1-m4.md §4.3). A
// Nitro VM's vCPUs and memory come from the Nitro System, not from what the
// node's admitter counts, and it has limits of its own (Firecracker's Nitro
// Sandboxes guide and the AWS user guide):
//
//   - all sandboxes together get at most 5 vCPUs per host vCPU (CPU
//     overcommit is always on here, nitro.go putEnclave);
//   - each takes from the memory pool reserved at boot
//     (nitro_enclaves.mempool) its memory, a 2 MiB control page and, in
//     confidential mode, a 16 MiB buffer per virtual device;
//   - each holds one of the device's PCIe slots while it runs. A freshly
//     booted machine has 4 (pcie_slots); writing a higher target to
//     pcie_slots grows them in steps of 8, up to pcie_slots_total, and each
//     step takes 128 MiB of the pool until the machine reboots.
//
// nitroBudget holds each running Nitro VM's share and refuses a boot (a
// create, or the start of a stopped sandbox) that would pass a limit, as a
// capacity refusal (503, retried elsewhere by the cluster). When the next
// VM needs a slot past the current ones, it grows them one step first: the
// live run m2-nitro-adm-1126 stopped at 4 sandboxes without that. A stopped
// VM holds nothing: its enclave is gone. The share is written in the VM's
// record, so a restarted sandboxd takes it back with the VM (adoptVM).

const (
	nitroVcpusPerHostVcpu = 5
	nitroControlPageMiB   = 2
	nitroDeviceBufferMiB  = 16
	nitroBaseSlots        = 4
	nitroSlotStep         = 8
	nitroSlotStepMiB      = 128
	// nitroMinMemoryMiB is AWS's floor for a Nitro Sandbox ("Give each
	// Nitro Sandbox at least 256 MiB of memory"); memory comes in 2 MiB
	// steps. Checked here so a create learns before any work.
	nitroMinMemoryMiB = 256
)

// The refusals name the limit, not the node's numbers: a tenant learns
// which limit to wait for, not the server's size. The numbers are logged.
const (
	nitroVcpuPool  = "Nitro vCPU budget"
	nitroMemPool   = "Nitro memory pool"
	nitroSlotsPool = "Nitro PCIe slots"
)

// nitroSysfsDir is where the Nitro Enclaves driver reports its pools. A
// variable for tests.
var nitroSysfsDir = "/sys/class/misc/nitro_enclaves"

// nitroHold is one VM's share: its vCPUs, and the pool memory it takes
// (memory, control page and device buffers).
type nitroHold struct{ vcpus, memMiB int }

type nitroBudget struct {
	mu        sync.Mutex
	loaded    bool
	hostVcpus int
	// poolMiB and slotsTotal are 0 when the device does not report them:
	// that limit is then not checked (Firecracker still refuses past it,
	// nitroOutOfResources).
	poolMiB    int
	slotsTotal int
	held       map[string]nitroHold
	logger     *slog.Logger
	// The device, as seams for tests: its fixed limits; its current slots
	// (0: not reported, so never grown); growing them.
	readLimits func() (poolMiB, slotsTotal int)
	readSlots  func() int
	writeSlots func(target int) error
}

func newNitroBudget(hostVcpus int, logger *slog.Logger) *nitroBudget {
	return &nitroBudget{hostVcpus: hostVcpus, held: map[string]nitroHold{}, logger: logger,
		readLimits: readNitroDevice, readSlots: func() int { return readNitroSysfs("pcie_slots") }, writeSlots: writeNitroSlots}
}

func readNitroSysfs(name string) int {
	raw, err := os.ReadFile(filepath.Join(nitroSysfsDir, name))
	if err != nil {
		return 0
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || n < 0 {
		return 0
	}
	return int(n)
}

// readNitroDevice reads mem_pool/total (bytes) and pcie_slots_total.
func readNitroDevice() (poolMiB, slotsTotal int) {
	return readNitroSysfs("mem_pool/total") >> 20, readNitroSysfs("pcie_slots_total")
}

// writeNitroSlots asks the driver for at least target slots; it rounds up
// to the next step of 8. ENOMEM: the pool cannot give the step's memory.
func writeNitroSlots(target int) error {
	// Never create it: a missing attribute is a missing driver.
	f, err := os.OpenFile(filepath.Join(nitroSysfsDir, "pcie_slots"), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := f.Write([]byte(strconv.Itoa(target)))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// load reads the device's limits once, at the first boot rather than at
// driver construction, which does no I/O.
func (b *nitroBudget) loadLocked() {
	if b.loaded {
		return
	}
	b.loaded = true
	b.poolMiB, b.slotsTotal = b.readLimits()
	if b.logger != nil {
		b.logger.Info("firecracker nitro: limits", "sandbox_vcpus", b.hostVcpus*nitroVcpusPerHostVcpu,
			"memory_pool_mib", b.poolMiB, "pcie_slots_total", b.slotsTotal, "pcie_slots", b.readSlots())
	}
}

func (b *nitroBudget) usedLocked() nitroHold {
	var used nitroHold
	for _, h := range b.held {
		used.vcpus += h.vcpus
		used.memMiB += h.memMiB
	}
	return used
}

// slotStepsMiB is the pool memory that slots took to grow to slots.
func slotStepsMiB(slots int) int {
	if slots <= nitroBaseSlots {
		return 0
	}
	return (slots - nitroBaseSlots + nitroSlotStep - 1) / nitroSlotStep * nitroSlotStepMiB
}

// nitroPoolNeed is the pool memory a VM of memMiB with devices virtual
// devices takes: its memory, the control page and, in confidential mode,
// a buffer per device.
func nitroPoolNeed(memMiB, devices int, confidential bool) int {
	need := memMiB + nitroControlPageMiB
	if confidential {
		need += devices * nitroDeviceBufferMiB
	}
	return need
}

// reserve holds a share for id, growing the PCIe slots a step when the VM
// needs one past them, or refuses with the limit it would pass. A second
// reserve for the same id holds nothing more.
func (b *nitroBudget) reserve(id string, vcpus, needMiB int) error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.loadLocked()
	if _, ok := b.held[id]; ok {
		return nil
	}
	used := b.usedLocked()
	running := len(b.held)
	slots := b.readSlots()
	grow := slots > 0 && running+1 > slots
	stepsMiB := slotStepsMiB(slots)
	if grow {
		stepsMiB = slotStepsMiB(running + 1)
	}
	pool := ""
	switch {
	case used.vcpus+vcpus > b.hostVcpus*nitroVcpusPerHostVcpu:
		pool = nitroVcpuPool
	case b.slotsTotal > 0 && running+1 > b.slotsTotal:
		pool = nitroSlotsPool
	case b.poolMiB > 0 && used.memMiB+needMiB+stepsMiB > b.poolMiB:
		pool = nitroMemPool
	}
	if pool == "" && grow {
		if err := b.writeSlots(running + 1); err != nil {
			pool = nitroSlotsPool
			if errors.Is(err, syscall.ENOMEM) {
				pool = nitroMemPool
			}
			if b.logger != nil {
				b.logger.Warn("firecracker nitro: growing the PCIe slots failed", "sandbox_id", id, "pcie_slots", slots, "target", running+1, "error", err)
			}
		}
	}
	if pool != "" {
		if b.logger != nil {
			b.logger.Info("firecracker nitro: boot refused", "sandbox_id", id, "limit", pool,
				"ask_vcpus", vcpus, "ask_pool_mib", needMiB, "used_vcpus", used.vcpus, "used_pool_mib", used.memMiB,
				"slot_steps_mib", stepsMiB, "running", running, "pcie_slots", slots, "pcie_slots_total", b.slotsTotal,
				"sandbox_vcpus", b.hostVcpus*nitroVcpusPerHostVcpu, "memory_pool_mib", b.poolMiB)
		}
		return capacity.NewSlotPoolExhausted(pool)
	}
	b.held[id] = nitroHold{vcpus: vcpus, memMiB: needMiB}
	return nil
}

// adopt takes back the share of a VM that already runs (a restarted
// sandboxd): it is counted whatever the limits say, since it is there.
func (b *nitroBudget) adopt(id string, h nitroHold) {
	if b == nil || h.vcpus < 1 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.held[id] = h
}

func (b *nitroBudget) release(id string) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.held, id)
}

func (b *nitroBudget) holding(id string) (nitroHold, bool) {
	if b == nil {
		return nitroHold{}, false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	h, ok := b.held[id]
	return h, ok
}

// nitroHostPool names a refusal by the Nitro System itself.
const nitroHostPool = "Nitro resources"

// nitroOutOfResources turns the Nitro System refusing a VM at InstanceStart
// for want of resources into a capacity refusal (503, retried elsewhere),
// or returns nil for any other error. The budget cannot see every limit:
// in the live run m2-nitro-adm-1126 the 5th VM after ten deleted ones was
// refused with ENOSPC ("Failed to create enclave VM: No space left") while
// the budget had room, most likely because a deleted VM's memory returns
// to the pool some time after it ends. Firecracker's words go to the log;
// the caller gets the limit's name, as for the budget's own refusals.
func (d *Driver) nitroOutOfResources(sandboxID string, err error) error {
	if !d.nitro() || err == nil || !strings.Contains(err.Error(), "No space left") {
		return nil
	}
	if d.logger != nil {
		d.logger.Info("firecracker nitro: the Nitro System refused the VM for want of resources", "sandbox_id", sandboxID, "error", err)
	}
	return capacity.NewSlotPoolExhausted(nitroHostPool)
}

// slotPool is the vCPU budget as a slot pool for placement: one slot per
// sandbox vCPU, so a node with none left gets no Nitro creates. A node
// with one left may still refuse a two-vCPU create; the cluster then tries
// another, as for any capacity refusal.
func (b *nitroBudget) slotPool() capacity.SlotPool {
	b.mu.Lock()
	defer b.mu.Unlock()
	total := b.hostVcpus * nitroVcpusPerHostVcpu
	return capacity.SlotPool{
		Name:     capacity.SlotPoolNitroVcpus,
		Runtimes: []string{models.RuntimeFirecrackerNitro},
		Total:    total,
		Free:     max(total-b.usedLocked().vcpus, 0),
	}
}

// nitroNeed is the pool memory one of this node's VMs takes: the root
// disk, the network and vsock, and an overlay disk when it has one.
func (d *Driver) nitroNeed(memMiB int, overlay bool) int {
	devices := 3
	if overlay {
		devices++
	}
	return nitroPoolNeed(memMiB, devices, d.cfg.NitroMode == config.FirecrackerNitroModeConfidential)
}

// NitroSlotPool is the driver's Nitro vCPU budget for the service's slot
// pools (internal/service slot_pools.go); false on a KVM node.
func (d *Driver) NitroSlotPool() (capacity.SlotPool, bool) {
	if !d.nitro() || d.budget == nil {
		return capacity.SlotPool{}, false
	}
	return d.budget.slotPool(), true
}

// checkNitroShape refuses, before any work, a memory size a Nitro Sandbox
// cannot have.
func checkNitroShape(memMiB int) error {
	if memMiB < nitroMinMemoryMiB || memMiB%2 != 0 {
		return fmt.Errorf("runtime %q needs memory_mb to be an even number, at least %d; got %d",
			models.RuntimeFirecrackerNitro, nitroMinMemoryMiB, memMiB)
	}
	return nil
}
