// Package capacity implements admission control for sandbox creation.
//
// The admitter combines three signals before letting a sandbox in:
//
//  1. A simple count cap (MaxSandboxes) — the crudest backstop.
//  2. Sum-of-reservations against host CPU cores and total memory, scaled by
//     configurable ratios. This is predictable: the operator knows that
//     accepted requests will not collectively exceed the ratio of host
//     capacity, regardless of whether the sandboxes are actually using it.
//  3. A live free-memory floor read from /proc/meminfo. This catches the case
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
	// MaxSandboxes caps the number of concurrent sandboxes. 0 = unlimited.
	MaxSandboxes int
	// CPUReservationRatio is the maximum fraction of host CPU cores that may
	// be reserved across all sandboxes. 0 = unlimited.
	CPUReservationRatio float64
	// MemoryReservationRatio is the maximum fraction of host memory that may
	// be reserved across all sandboxes. 0 = unlimited.
	MemoryReservationRatio float64
	// MemoryFloorMB is the minimum live MemAvailable the host must report
	// after admitting the request. 0 = no floor.
	MemoryFloorMB int
}

// Request is the per-sandbox resource ask, in normalized units.
type Request struct {
	CPU      int
	MemoryMB int
}

// Snapshot is a read-only view of admitter state, suitable for an HTTP
// /capacity response.
type Snapshot struct {
	HostCPUCores      int     `json:"host_cpu_cores"`
	HostMemoryTotalMB int     `json:"host_memory_total_mb"`
	ReservedCPU       int     `json:"reserved_cpu"`
	ReservedMemoryMB  int     `json:"reserved_memory_mb"`
	LiveMemoryFreeMB  int     `json:"live_memory_free_mb"`
	SandboxesActive   int     `json:"sandboxes_active"`
	SandboxesMax      int     `json:"sandboxes_max"`
	CanAdmit          bool    `json:"can_admit"`
	Reasons           []string `json:"reasons,omitempty"`
	CPUReservationRatio    float64 `json:"cpu_reservation_ratio"`
	MemoryReservationRatio float64 `json:"memory_reservation_ratio"`
	MemoryFloorMB          int     `json:"memory_floor_mb"`
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
	totalCPU     int
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
	projectedCount := len(a.reservations)
	if !exists {
		projectedCount++
	}

	var reasons []string

	if a.limits.MaxSandboxes > 0 && projectedCount > a.limits.MaxSandboxes {
		reasons = append(reasons, fmt.Sprintf(
			"max sandboxes reached (%d/%d)",
			len(a.reservations), a.limits.MaxSandboxes,
		))
	}

	if a.limits.CPUReservationRatio > 0 && a.host.CPUCores > 0 {
		cpuBudget := int(float64(a.host.CPUCores) * a.limits.CPUReservationRatio)
		if cpuBudget < 1 {
			cpuBudget = 1
		}
		if projectedCPU > cpuBudget {
			reasons = append(reasons, fmt.Sprintf(
				"cpu reservation exceeded (%d+%d > %d budget)",
				a.totalCPU, req.CPU, cpuBudget,
			))
		}
	}

	if a.limits.MemoryReservationRatio > 0 && a.host.MemoryTotalMB > 0 {
		memBudget := int(float64(a.host.MemoryTotalMB) * a.limits.MemoryReservationRatio)
		if projectedMem > memBudget {
			reasons = append(reasons, fmt.Sprintf(
				"memory reservation exceeded (%d+%d MB > %d MB budget)",
				a.totalMemMB, req.MemoryMB, memBudget,
			))
		}
	}

	if a.limits.MemoryFloorMB > 0 && a.probe != nil {
		free, err := a.probe.FreeMB()
		// Probe failure is treated as "unknown, allow" — we'd rather admit
		// occasionally over a transient probe error than wedge the daemon.
		if err == nil && free-req.MemoryMB < a.limits.MemoryFloorMB {
			reasons = append(reasons, fmt.Sprintf(
				"live memory floor breached (%d-%d MB free < %d MB floor)",
				free, req.MemoryMB, a.limits.MemoryFloorMB,
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
		HostCPUCores:           a.host.CPUCores,
		HostMemoryTotalMB:      a.host.MemoryTotalMB,
		ReservedCPU:            totalCPU,
		ReservedMemoryMB:       totalMem,
		LiveMemoryFreeMB:       free,
		SandboxesActive:        count,
		SandboxesMax:           a.limits.MaxSandboxes,
		CPUReservationRatio:    a.limits.CPUReservationRatio,
		MemoryReservationRatio: a.limits.MemoryReservationRatio,
		MemoryFloorMB:          a.limits.MemoryFloorMB,
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
	count := len(a.reservations)
	totalCPU := a.totalCPU
	totalMem := a.totalMemMB
	a.mu.Unlock()

	var reasons []string
	if a.limits.MaxSandboxes > 0 && count+1 > a.limits.MaxSandboxes {
		reasons = append(reasons, fmt.Sprintf("max sandboxes reached (%d/%d)", count, a.limits.MaxSandboxes))
	}
	if a.limits.CPUReservationRatio > 0 && a.host.CPUCores > 0 {
		cpuBudget := int(float64(a.host.CPUCores) * a.limits.CPUReservationRatio)
		if cpuBudget < 1 {
			cpuBudget = 1
		}
		if totalCPU+req.CPU > cpuBudget {
			reasons = append(reasons, fmt.Sprintf("cpu reservation exceeded (%d/%d)", totalCPU, cpuBudget))
		}
	}
	if a.limits.MemoryReservationRatio > 0 && a.host.MemoryTotalMB > 0 {
		memBudget := int(float64(a.host.MemoryTotalMB) * a.limits.MemoryReservationRatio)
		if totalMem+req.MemoryMB > memBudget {
			reasons = append(reasons, fmt.Sprintf("memory reservation exceeded (%d MB/%d MB)", totalMem, memBudget))
		}
	}
	if a.limits.MemoryFloorMB > 0 && a.probe != nil {
		if free, err := a.probe.FreeMB(); err == nil && free-req.MemoryMB < a.limits.MemoryFloorMB {
			reasons = append(reasons, fmt.Sprintf("live memory floor breached (%d MB free, %d MB floor)", free, a.limits.MemoryFloorMB))
		}
	}
	return len(reasons) == 0, reasons
}
