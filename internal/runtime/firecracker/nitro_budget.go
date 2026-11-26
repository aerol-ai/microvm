package firecracker

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
)

// Admission on the Nitro backend (plans/security-gaps-m1-m4.md §4.3). A
// Nitro VM's vCPUs and memory come from the Nitro System, not from what the
// node's admitter counts, and it has limits of its own (Firecracker's Nitro
// Sandboxes guide, "Sandbox limits"; the SP-B spike hit them):
//
//   - all sandboxes together get at most 5 vCPUs per host vCPU (CPU
//     overcommit is always on here, nitro.go putEnclave);
//   - each takes its memory plus a 2 MiB control page from the memory pool
//     reserved at boot (nitro_enclaves.mempool), never from free memory;
//   - each holds one of the device's PCIe slots while it runs.
//
// nitroBudget holds each running Nitro VM's share and refuses a boot (a
// create, or the start of a stopped sandbox) that would pass any limit, as
// a capacity refusal (503, retried elsewhere by the cluster). A stopped VM
// holds nothing: its enclave is gone. The share is written in the VM's
// record, so a restarted sandboxd takes it back with the VM (adoptVM).

const (
	nitroVcpusPerHostVcpu = 5
	nitroControlPageMiB   = 2
	// nitroMinMemoryMiB and the 2 MiB step are Firecracker's own rules for
	// a Nitro Sandbox; checked here so a create learns before any work.
	nitroMinMemoryMiB = 64
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

type nitroHold struct{ vcpus, memMiB int }

type nitroBudget struct {
	mu        sync.Mutex
	loaded    bool
	hostVcpus int
	// poolMiB and slots are 0 when the device does not report them: that
	// limit is then not checked (Firecracker still refuses past it).
	poolMiB int
	slots   int
	held    map[string]nitroHold
	logger  *slog.Logger
	// readDevice reads the device's limits; a seam for tests.
	readDevice func() (poolMiB, slots int)
}

func newNitroBudget(hostVcpus int, logger *slog.Logger) *nitroBudget {
	return &nitroBudget{hostVcpus: hostVcpus, held: map[string]nitroHold{}, logger: logger, readDevice: readNitroDevice}
}

// readNitroDevice reads mem_pool/total (bytes) and pcie_slots_total.
func readNitroDevice() (poolMiB, slots int) {
	read := func(name string) int {
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
	return read("mem_pool/total") >> 20, read("pcie_slots_total")
}

// load reads the device's limits once, at the first boot rather than at
// driver construction, which does no I/O.
func (b *nitroBudget) loadLocked() {
	if b.loaded {
		return
	}
	b.loaded = true
	b.poolMiB, b.slots = b.readDevice()
	if b.logger != nil {
		b.logger.Info("firecracker nitro: limits", "sandbox_vcpus", b.hostVcpus*nitroVcpusPerHostVcpu,
			"memory_pool_mib", b.poolMiB, "pcie_slots", b.slots)
	}
}

func (b *nitroBudget) usedLocked() nitroHold {
	var used nitroHold
	for _, h := range b.held {
		used.vcpus += h.vcpus
		used.memMiB += h.memMiB + nitroControlPageMiB
	}
	return used
}

// reserve holds a share for id, or refuses with the limit it would pass.
// A second reserve for the same id holds nothing more.
func (b *nitroBudget) reserve(id string, vcpus, memMiB int) error {
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
	pool := ""
	switch {
	case used.vcpus+vcpus > b.hostVcpus*nitroVcpusPerHostVcpu:
		pool = nitroVcpuPool
	case b.poolMiB > 0 && used.memMiB+memMiB+nitroControlPageMiB > b.poolMiB:
		pool = nitroMemPool
	case b.slots > 0 && len(b.held)+1 > b.slots:
		pool = nitroSlotsPool
	}
	if pool != "" {
		if b.logger != nil {
			b.logger.Info("firecracker nitro: boot refused", "sandbox_id", id, "limit", pool,
				"ask_vcpus", vcpus, "ask_memory_mib", memMiB, "used_vcpus", used.vcpus, "used_memory_mib", used.memMiB,
				"running", len(b.held), "sandbox_vcpus", b.hostVcpus*nitroVcpusPerHostVcpu, "memory_pool_mib", b.poolMiB, "pcie_slots", b.slots)
		}
		return capacity.NewSlotPoolExhausted(pool)
	}
	b.held[id] = nitroHold{vcpus: vcpus, memMiB: memMiB}
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
