// Package capacity implements admission control for sandbox creation.
//
// Admission is purely resource-math — there is no fixed "max sandboxes"
// number. The admitter combines two signals before letting a sandbox in:
//
//  1. Sum-of-reservations against host CPU cores and total memory, scaled by
//     configurable ratios. This is predictable: the operator knows that
//     accepted requests will not collectively exceed the ratio of host
//     capacity, regardless of whether the sandboxes are actually using it.
//     A 64-core box can run 200 tiny sandboxes or 8 huge ones — whatever the
//     math allows.
//  2. A live free-memory floor read from /proc/meminfo. This catches the case
//     where reservations look fine but the host is genuinely tight right now
//     (e.g. another process is eating RAM).
//
// Reservations are tracked in-process. They must be replayed at startup from
// persistent state so a daemon restart doesn't reset accounting to zero.
package capacity

import (
	"errors"
	"fmt"
	"runtime"
	"sync"
)

// ErrCapacityExceeded is returned by Admit when the host cannot accept a new
// sandbox. The wrapped error carries human-readable reasons; callers can use
// errors.Is to map this to a 503 response.
var ErrCapacityExceeded = errors.New("host capacity exceeded")

// Limits configures the admitter. Zero values disable the corresponding check.
type Limits struct {
	// CPUReservationRatio is the maximum fraction of host CPU cores that may
	// be reserved across all sandboxes. 0 = unlimited.
	CPUReservationRatio float64
	// MemoryReservationRatio is the maximum fraction of host memory that may
	// be reserved across all sandboxes. 0 = unlimited.
	MemoryReservationRatio float64
	// MemoryFloorRatio is the minimum live MemAvailable the host must retain
	// after admitting the request, expressed as a fraction of total host
	// memory (e.g. 0.05 = keep at least 5% of RAM free). Expressing this as a
	// ratio means a 16 GB laptop and a 256 GB box scale their headroom
	// proportionally — a fixed MB floor would be either pointless on big
	// hosts or starve small ones. 0 = no floor.
	MemoryFloorRatio float64
	// CPUOverProvisionFactor multiplies the CPU reservation budget. Docker
	// --cpus is a CFS cap, not a hard reservation, so idle sandboxes share
	// cores happily — a 10× default lets typical workloads pack densely.
	// Values below 1.0 are clamped to 1.0 (no overcommit). 0 is treated as
	// the default 1.0 so a zero-value Limits behaves as before.
	CPUOverProvisionFactor float64
	// MemoryOverProvisionFactor multiplies the memory reservation budget.
	// Memory pressure is harder to recover from than CPU contention (OOM
	// killer fires on hard limits), so the live MemoryFloorRatio check is
	// the real backstop when this is set high. Same clamping as the CPU
	// factor.
	MemoryOverProvisionFactor float64
}

// Request is the per-sandbox resource ask, in normalized units. CPU is
// fractional cores (e.g. 0.5 = half a core); memory is whole MB.
type Request struct {
	CPU      float64
	MemoryMB int
}

// Snapshot is a read-only view of admitter state, suitable for an HTTP
// /capacity response.
type Snapshot struct {
	HostCPUCores      int      `json:"host_cpu_cores"`
	HostMemoryTotalMB int      `json:"host_memory_total_mb"`
	ReservedCPU       float64  `json:"reserved_cpu"`
	ReservedMemoryMB  int      `json:"reserved_memory_mb"`
	LiveMemoryFreeMB  int      `json:"live_memory_free_mb"`
	SandboxesActive   int      `json:"sandboxes_active"`
	CanAdmit          bool     `json:"can_admit"`
	Reasons           []string `json:"reasons,omitempty"`
	CPUReservationRatio       float64 `json:"cpu_reservation_ratio"`
	MemoryReservationRatio    float64 `json:"memory_reservation_ratio"`
	MemoryFloorRatio          float64 `json:"memory_floor_ratio"`
	CPUOverProvisionFactor    float64 `json:"cpu_overprovision_factor"`
	MemoryOverProvisionFactor float64 `json:"memory_overprovision_factor"`
	// MemoryFloorMB is the absolute floor derived from MemoryFloorRatio and
	// host memory, exposed for operators reading /capacity.
	MemoryFloorMB int `json:"memory_floor_mb"`
	// CPUBudget and MemoryBudgetMB are the post-overcommit budgets actually
	// used by Admit, exposed so operators can see the effective ceiling.
	CPUBudget      float64 `json:"cpu_budget"`
	MemoryBudgetMB int     `json:"memory_budget_mb"`
}

// MemProbe reports live free memory in MB. The default implementation reads
// /proc/meminfo MemAvailable. Tests can substitute a fake.
type MemProbe interface {
	FreeMB() (int, error)
}

// HostInfo describes the static host capacity.
type HostInfo struct {
	CPUCores      int
	MemoryTotalMB int
}

// Admitter is the thread-safe admission controller. Construct with New and
// keep a single instance per daemon.
type Admitter struct {
	host   HostInfo
	limits Limits
	probe  MemProbe

	mu           sync.Mutex
	reservations map[string]Request
	totalCPU     float64
	totalMemMB   int
}

// New builds an admitter. host should reflect the machine's total capacity;
// callers that don't care about per-host detection can use DetectHost.
func New(host HostInfo, limits Limits, probe MemProbe) *Admitter {
	return &Admitter{
		host:         host,
		limits:       limits,
		probe:        probe,
		reservations: make(map[string]Request),
	}
}

// DetectHost returns CPU core count from runtime and memory total from
// /proc/meminfo via the default probe. Callers may override either field.
func DetectHost() (HostInfo, error) {
	mem, err := totalMemoryMB()
	if err != nil {
		return HostInfo{}, fmt.Errorf("read host memory: %w", err)
	}
	return HostInfo{
		CPUCores:      runtime.NumCPU(),
		MemoryTotalMB: mem,
	}, nil
}

// Admit decides whether a new sandbox with the given resource request can be
// accepted right now. On success it reserves the request under sandboxID and
// returns nil. On failure it returns an error wrapping ErrCapacityExceeded
// with reasons attached; no reservation is made.
//
// Callers that fail downstream (e.g. docker create errors) must call Release
// to free the reservation. Reserve is idempotent per sandboxID — re-admitting
// the same ID overwrites the prior reservation.
func (a *Admitter) Admit(sandboxID string, req Request) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Reservation check — what the future state would be if we accept.
	prior, exists := a.reservations[sandboxID]
	projectedCPU := a.totalCPU + req.CPU
	projectedMem := a.totalMemMB + req.MemoryMB
	if exists {
		projectedCPU -= prior.CPU
		projectedMem -= prior.MemoryMB
	}

	var reasons []string

	if a.limits.CPUReservationRatio > 0 && a.host.CPUCores > 0 {
		cpuBudget := a.cpuBudget()
		if projectedCPU > cpuBudget {
			reasons = append(reasons, fmt.Sprintf(
				"cpu reservation exceeded (%.2f+%.2f > %.2f budget)",
				a.totalCPU, req.CPU, cpuBudget,
			))
		}
	}

	if a.limits.MemoryReservationRatio > 0 && a.host.MemoryTotalMB > 0 {
		memBudget := a.memBudgetMB()
		if projectedMem > memBudget {
			reasons = append(reasons, fmt.Sprintf(
				"memory reservation exceeded (%d+%d MB > %d MB budget)",
				a.totalMemMB, req.MemoryMB, memBudget,
			))
		}
	}

	if floor := a.memoryFloorMB(); floor > 0 && a.probe != nil {
		free, err := a.probe.FreeMB()
		// Probe failure is treated as "unknown, allow" — we'd rather admit
		// occasionally over a transient probe error than wedge the daemon.
		if err == nil && free-req.MemoryMB < floor {
			reasons = append(reasons, fmt.Sprintf(
				"live memory floor breached (%d-%d MB free < %d MB floor)",
				free, req.MemoryMB, floor,
			))
		}
	}

	if len(reasons) > 0 {
		return fmt.Errorf("%w: %v", ErrCapacityExceeded, reasons)
	}

	if exists {
		a.totalCPU -= prior.CPU
		a.totalMemMB -= prior.MemoryMB
	}
	a.reservations[sandboxID] = req
	a.totalCPU += req.CPU
	a.totalMemMB += req.MemoryMB
	return nil
}

// Release frees the reservation for sandboxID. Safe to call for unknown IDs.
func (a *Admitter) Release(sandboxID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	prior, ok := a.reservations[sandboxID]
	if !ok {
		return
	}
	delete(a.reservations, sandboxID)
	a.totalCPU -= prior.CPU
	a.totalMemMB -= prior.MemoryMB
}

// Reserve records a reservation without running admission checks. Use this on
// startup to replay existing sandboxes from persistent state. Subsequent
// Admit calls see the replayed reservations as already-counted.
func (a *Admitter) Reserve(sandboxID string, req Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if prior, ok := a.reservations[sandboxID]; ok {
		a.totalCPU -= prior.CPU
		a.totalMemMB -= prior.MemoryMB
	}
	a.reservations[sandboxID] = req
	a.totalCPU += req.CPU
	a.totalMemMB += req.MemoryMB
}

// Snapshot returns a point-in-time view. Includes a CanAdmit answer for a
// hypothetical zero-resource sandbox so operators can see "is this host
// accepting at all" without having to make a real request.
func (a *Admitter) Snapshot() Snapshot {
	a.mu.Lock()
	count := len(a.reservations)
	totalCPU := a.totalCPU
	totalMem := a.totalMemMB
	a.mu.Unlock()

	free := 0
	if a.probe != nil {
		if v, err := a.probe.FreeMB(); err == nil {
			free = v
		}
	}

	snap := Snapshot{
		HostCPUCores:              a.host.CPUCores,
		HostMemoryTotalMB:         a.host.MemoryTotalMB,
		ReservedCPU:               totalCPU,
		ReservedMemoryMB:          totalMem,
		LiveMemoryFreeMB:          free,
		SandboxesActive:           count,
		CPUReservationRatio:       a.limits.CPUReservationRatio,
		MemoryReservationRatio:    a.limits.MemoryReservationRatio,
		MemoryFloorRatio:          a.limits.MemoryFloorRatio,
		CPUOverProvisionFactor:    a.cpuOverProvisionFactor(),
		MemoryOverProvisionFactor: a.memOverProvisionFactor(),
		MemoryFloorMB:             a.memoryFloorMB(),
		CPUBudget:                 a.cpuBudget(),
		MemoryBudgetMB:            a.memBudgetMB(),
	}
	// Use the smallest meaningful request (1 CPU, 1 MB) as the probe ask.
	// We don't use 0/0 because that bypasses every check and would always
	// report CanAdmit=true even when the host is full.
	snap.CanAdmit, snap.Reasons = a.dryRun(Request{CPU: 1, MemoryMB: 1})
	return snap
}

// dryRun is Admit's check-only path — it returns whether a request would be
// admitted right now and the reasons if not, without mutating state.
func (a *Admitter) dryRun(req Request) (bool, []string) {
	a.mu.Lock()
	totalCPU := a.totalCPU
	totalMem := a.totalMemMB
	a.mu.Unlock()

	var reasons []string
	if a.limits.CPUReservationRatio > 0 && a.host.CPUCores > 0 {
		cpuBudget := a.cpuBudget()
		if totalCPU+req.CPU > cpuBudget {
			reasons = append(reasons, fmt.Sprintf("cpu reservation exceeded (%.2f/%.2f)", totalCPU, cpuBudget))
		}
	}
	if a.limits.MemoryReservationRatio > 0 && a.host.MemoryTotalMB > 0 {
		memBudget := a.memBudgetMB()
		if totalMem+req.MemoryMB > memBudget {
			reasons = append(reasons, fmt.Sprintf("memory reservation exceeded (%d MB/%d MB)", totalMem, memBudget))
		}
	}
	if floor := a.memoryFloorMB(); floor > 0 && a.probe != nil {
		if free, err := a.probe.FreeMB(); err == nil && free-req.MemoryMB < floor {
			reasons = append(reasons, fmt.Sprintf("live memory floor breached (%d MB free, %d MB floor)", free, floor))
		}
	}
	return len(reasons) == 0, reasons
}

// memoryFloorMB resolves the configured ratio against current host memory.
// Returns 0 when no floor is configured or host memory is unknown.
func (a *Admitter) memoryFloorMB() int {
	if a.limits.MemoryFloorRatio <= 0 || a.host.MemoryTotalMB <= 0 {
		return 0
	}
	return int(float64(a.host.MemoryTotalMB) * a.limits.MemoryFloorRatio)
}

// cpuOverProvisionFactor returns the effective CPU overcommit multiplier.
// 0 or any value <1 is clamped to 1.0 so callers that don't set the field
// (and tests that predate it) keep their original "fits exactly to host"
// semantics.
func (a *Admitter) cpuOverProvisionFactor() float64 {
	if a.limits.CPUOverProvisionFactor < 1 {
		return 1
	}
	return a.limits.CPUOverProvisionFactor
}

func (a *Admitter) memOverProvisionFactor() float64 {
	if a.limits.MemoryOverProvisionFactor < 1 {
		return 1
	}
	return a.limits.MemoryOverProvisionFactor
}

// cpuBudget is the post-overcommit reservation ceiling: cores × ratio × factor.
// Floored at 0.01 so a host with extreme ratios still admits the smallest
// fractional ask we model.
func (a *Admitter) cpuBudget() float64 {
	budget := float64(a.host.CPUCores) * a.limits.CPUReservationRatio * a.cpuOverProvisionFactor()
	if budget < 0.01 {
		budget = 0.01
	}
	return budget
}

func (a *Admitter) memBudgetMB() int {
	return int(float64(a.host.MemoryTotalMB) * a.limits.MemoryReservationRatio * a.memOverProvisionFactor())
}
