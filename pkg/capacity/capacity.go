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
	"os"
	"runtime"
	"sync"
	"syscall"
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
	// DiskReservationRatio is the maximum fraction of host disk that may be
	// reserved across all sandboxes. Disk is sized in GB rather than MB
	// because Docker's --storage-opt size is GB-granular and operators
	// reason about disk in GB. 0 = unlimited.
	DiskReservationRatio float64
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
	// RSSWatermarkRatio is the Phase 5 memory-overcommit safety floor,
	// expressed as a fraction of host memory. Admission rejects a
	// request when EffectiveMemoryFree (HostMem - sum-of-VMM-RSS) would
	// drop below this watermark after admit. 0 disables the check (the
	// default) — operators opt in by setting the env var, and the check
	// is also gated on a non-nil RSSSource whose Ready() returns true,
	// so a pre-tick daemon falls back to nominal accounting. The point
	// of this axis is to safely raise MemoryOverProvisionFactor:
	// nominal accounting caps you at "host RAM × ratio × factor" but
	// can't see whether VMMs are actually touching the memory they
	// reserved; the watermark says "regardless of nominal, keep this
	// much real free RAM in reserve for the next RSS spike."
	RSSWatermarkRatio float64
}

// Request is the per-sandbox resource ask, in normalized units. CPU is
// fractional cores (e.g. 0.5 = half a core); memory is whole MB; disk is
// whole GB. GPUs is the count requested (0 = no GPU); GPUVendor is the
// required vendor when GPUs > 0 and is matched against HostInfo.GPUVendor
// at admission/placement time. Runtime is the OCI runtime identifier
// ("docker", "gvisor", ...) — empty means "any runtime the host supports."
// TemplateID, when set alongside Runtime="firecracker", lets placement
// prefer (and gate on) peers that already have the template's artifacts
// cached locally — empty means "any host," matching pre-Phase-6 behaviour.
type Request struct {
	CPU        float64
	MemoryMB   int
	DiskGB     int
	GPUs       int
	GPUVendor  string
	Runtime    string
	TemplateID string
	// ModuleRef, when set alongside Runtime="wasm", lets cluster placement
	// prefer peers that already have the module cached locally.
	ModuleRef string
	// RequiredNodeID pins non-portable local artifacts (for example an image
	// built on one worker) to the only node that can satisfy the request.
	RequiredNodeID string
}

// Snapshot is a read-only view of admitter state, suitable for an HTTP
// /capacity response. It is also the payload in cluster capacity heartbeats:
// every field needed to decide "can this peer host this request?" must be
// present here, otherwise placement scores against stale assumptions and the
// caller fans out to a node that can't actually admit.
type Snapshot struct {
	HostCPUCores      int     `json:"host_cpu_cores"`
	HostMemoryTotalMB int     `json:"host_memory_total_mb"`
	HostDiskTotalGB   int     `json:"host_disk_total_gb,omitempty"`
	HostDiskFreeGB    int     `json:"host_disk_free_gb,omitempty"`
	ReservedCPU       float64 `json:"reserved_cpu"`
	ReservedMemoryMB  int     `json:"reserved_memory_mb"`
	ReservedDiskGB    int     `json:"reserved_disk_gb,omitempty"`
	ReservedGPUs      int     `json:"reserved_gpus,omitempty"`
	AvailableCPU      float64 `json:"available_cpu"`
	AvailableMemoryMB int     `json:"available_memory_mb"`
	AvailableDiskGB   int     `json:"available_disk_gb,omitempty"`
	AvailableGPUs     int     `json:"available_gpus,omitempty"`
	LiveMemoryFreeMB  int     `json:"live_memory_free_mb"`
	SandboxesActive   int     `json:"sandboxes_active"`
	// SandboxesByRuntime is the live reservation count keyed by OCI runtime
	// ("docker"/containerd, "gvisor", "wasm", "isolate", "firecracker";
	// "unspecified" for a runtime-agnostic reservation). Lets dashboards show
	// live sandboxes broken down by isolation type — the bare SandboxesActive
	// gauge has no runtime label.
	SandboxesByRuntime        map[string]int `json:"sandboxes_by_runtime,omitempty"`
	CanAdmit                  bool           `json:"can_admit"`
	Reasons                   []string       `json:"reasons,omitempty"`
	CPUReservationRatio       float64        `json:"cpu_reservation_ratio"`
	MemoryReservationRatio    float64        `json:"memory_reservation_ratio"`
	DiskReservationRatio      float64        `json:"disk_reservation_ratio,omitempty"`
	MemoryFloorRatio          float64        `json:"memory_floor_ratio"`
	CPUOverProvisionFactor    float64        `json:"cpu_overprovision_factor"`
	MemoryOverProvisionFactor float64        `json:"memory_overprovision_factor"`
	// MemoryFloorMB is the absolute floor derived from MemoryFloorRatio and
	// host memory, exposed for operators reading /capacity.
	MemoryFloorMB int `json:"memory_floor_mb"`
	// Phase 5 effective-memory axis. ActualRSSMB is the live aggregate
	// from the per-VMM sampler; EffectiveMemoryFreeMB is the headroom
	// admission actually decides against (HostMem - ActualRSSMB);
	// RSSWatermarkMB is the absolute floor derived from
	// RSSWatermarkRatio. All four are 0 on hosts without a sampler so
	// peers running older binaries report 0 and placement falls back to
	// nominal accounting rather than treating "0" as "host is empty".
	ActualRSSMB           int     `json:"actual_rss_mb,omitempty"`
	EffectiveMemoryFreeMB int     `json:"effective_memory_free_mb,omitempty"`
	RSSWatermarkMB        int     `json:"rss_watermark_mb,omitempty"`
	RSSWatermarkRatio     float64 `json:"rss_watermark_ratio,omitempty"`
	// CPUBudget and MemoryBudgetMB are the post-overcommit budgets actually
	// used by Admit, exposed so operators can see the effective ceiling.
	CPUBudget      float64 `json:"cpu_budget"`
	MemoryBudgetMB int     `json:"memory_budget_mb"`
	DiskBudgetGB   int     `json:"disk_budget_gb,omitempty"`
	// GPUCount and GPUVendor are static node attributes set by the operator
	// (no auto-detection in Phase 1). Placement uses them to skip a peer
	// that cannot satisfy a GPU sandbox at all — running the admitter
	// remotely after a doomed forward would just 503.
	GPUCount  int    `json:"gpu_count,omitempty"`
	GPUVendor string `json:"gpu_vendor,omitempty"`
	// SupportedRuntimes lists the OCI runtimes this host can run
	// ("docker", "gvisor", ...). Used by placement to skip a peer that
	// doesn't have, say, runsc installed. Empty = legacy node, treated as
	// supporting any runtime so rolling upgrades don't strand pre-D peers.
	SupportedRuntimes []string `json:"supported_runtimes,omitempty"`
	// ContainerEngine is an observability tag (docker|containerd) so benches
	// and canary nodes compare engines like-for-like. Deliberately NOT a
	// placement attribute — see plans/containerd-engine.md §2 D18.
	ContainerEngine string `json:"container_engine,omitempty"`
	// LocalTemplateInventoryKnown distinguishes an authoritative empty
	// Firecracker template inventory from a legacy/unknown peer. When
	// false, placement treats LocalTemplateIDs as "unknown, allow" for
	// rolling upgrades and just-joined nodes. When true, an empty
	// LocalTemplateIDs slice means this host definitely has no local
	// templates cached.
	LocalTemplateInventoryKnown bool `json:"local_template_inventory_known,omitempty"`
	// LocalTemplateIDs lists the Firecracker templates whose artifact
	// files (rootfs.ext4 + snapshot.{memory,state}) are present on this
	// host. Placement gates a Firecracker create against it so a clone
	// against a template the target has never seen lands on a node that
	// already has it — preserving the <100ms boot promise. Consult
	// LocalTemplateInventoryKnown before treating an empty list as
	// authoritative: pre-upgrade peers omit both fields and degrade to
	// pre-feature behaviour, while known=true plus an empty list means
	// "definitely no local templates here."
	LocalTemplateIDs []string `json:"local_template_ids,omitempty"`
	// LocalWasmModuleInventoryKnown mirrors LocalTemplateInventoryKnown for
	// runtime=wasm module_ref placement (plans/wasm-runtime.md Phase 7).
	LocalWasmModuleInventoryKnown bool `json:"local_wasm_module_inventory_known,omitempty"`
	// LocalWasmModuleIDs lists module_ref values cached on this host.
	LocalWasmModuleIDs []string `json:"local_wasm_module_ids,omitempty"`
}

// MemProbe reports live free memory in MB. The default implementation reads
// /proc/meminfo MemAvailable. Tests can substitute a fake.
type MemProbe interface {
	FreeMB() (int, error)
}

// RSSSource is the Phase 5 bridge for the per-VMM RSS sampler that
// lives in internal/runtime/firecracker. The structural shape keeps
// pkg/capacity from importing the runtime package (and forming a
// cycle through main.go); the sampler satisfies the interface without
// declaring it.
//
// TotalRSSMB returns the most recent aggregate in MB; Ready reports
// whether the sampler has produced at least one observation. Admission
// only consults TotalRSSMB when Ready returns true — pre-tick, the
// "0 MB resident" reading is indistinguishable from "host is empty"
// and falsely admits under any non-zero RSSWatermarkRatio.
type RSSSource interface {
	TotalRSSMB() int
	Ready() bool
}

// HostInfo describes the static host capacity.
type HostInfo struct {
	CPUCores      int
	MemoryTotalMB int
	// DiskTotalGB is the disk budget for sandbox storage. It is auto-detected
	// from the host filesystem by default and can be overridden by
	// SB_HOST_DISK_GB when the sandbox pool is smaller than the filesystem.
	DiskTotalGB int
	// DiskFreeGB is the currently available space on the detected sandbox
	// storage filesystem. It is an observability signal; reservation
	// admission uses DiskTotalGB × DiskReservationRatio.
	DiskFreeGB int
	// GPUCount and GPUVendor describe the GPU inventory the operator has
	// wired up to Docker. Operator-declared (SB_HOST_GPU_COUNT /
	// SB_HOST_GPU_VENDOR); 0 means no GPUs available.
	GPUCount  int
	GPUVendor string
	// SupportedRuntimes lists the OCI runtimes installed on this host.
	// Empty defaults to []{"docker"} at Admitter construction so a node
	// that doesn't set the field still admits the common case.
	SupportedRuntimes []string
}

// Admitter is the thread-safe admission controller. Construct with New and
// keep a single instance per daemon.
type Admitter struct {
	host   HostInfo
	limits Limits
	probe  MemProbe
	rss    RSSSource // Phase 5; nil disables the RSS-watermark axis

	mu           sync.Mutex
	reservations map[string]Request
	totalCPU     float64
	totalMemMB   int
	totalDiskGB  int
	totalGPUs    int
}

// New builds an admitter. host should reflect the machine's total capacity;
// callers that don't care about per-host detection can use DetectHost.
//
// New constructs without an RSSSource (the Phase 5 memory-overcommit
// axis is disabled). Callers that want it should use NewWithRSSSource —
// kept as a separate constructor rather than adding a fifth positional
// arg here so existing call sites in tests and cluster bootstrapping
// stay untouched.
func New(host HostInfo, limits Limits, probe MemProbe) *Admitter {
	return NewWithRSSSource(host, limits, probe, nil)
}

// NewWithRSSSource builds an admitter wired to a Phase 5 RSS source.
// nil rss is equivalent to New — the watermark check is skipped.
func NewWithRSSSource(host HostInfo, limits Limits, probe MemProbe, rss RSSSource) *Admitter {
	// Default SupportedRuntimes to {"docker"} — every host that doesn't
	// override is by definition a docker host (this binary requires it).
	// Without this default, placement would treat unset SupportedRuntimes
	// as "supports nothing" the moment a request specified Runtime, which
	// is the opposite of the rolling-upgrade compatibility we want.
	if len(host.SupportedRuntimes) == 0 {
		host.SupportedRuntimes = []string{"docker"}
	}
	return &Admitter{
		host:         host,
		limits:       limits,
		probe:        probe,
		rss:          rss,
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
	diskTotal, diskFree, diskErr := detectDiskGB(defaultDiskPath())
	return HostInfo{
		CPUCores:      runtime.NumCPU(),
		MemoryTotalMB: mem,
		DiskTotalGB:   diskTotal,
		DiskFreeGB:    diskFree,
	}, diskErr
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
	projectedDisk := a.totalDiskGB + req.DiskGB
	projectedGPUs := a.totalGPUs + req.GPUs
	if exists {
		projectedCPU -= prior.CPU
		projectedMem -= prior.MemoryMB
		projectedDisk -= prior.DiskGB
		projectedGPUs -= prior.GPUs
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

	if a.limits.DiskReservationRatio > 0 && a.host.DiskTotalGB > 0 {
		diskBudget := a.diskBudgetGB()
		if projectedDisk > diskBudget {
			reasons = append(reasons, fmt.Sprintf(
				"disk reservation exceeded (%d+%d GB > %d GB budget)",
				a.totalDiskGB, req.DiskGB, diskBudget,
			))
		}
	}

	// GPU and runtime are not "budgets" the operator scales — they are
	// physical attributes of the host. We reject up front so a sandbox
	// that asked for GPUs never even tries to start on a GPU-less node;
	// silently letting docker fail later would leak partial state.
	if req.GPUs > 0 {
		if a.host.GPUCount <= 0 {
			reasons = append(reasons, "host has no GPUs")
		} else if projectedGPUs > a.host.GPUCount {
			reasons = append(reasons, fmt.Sprintf(
				"gpu reservation exceeded (%d+%d > %d available)",
				a.totalGPUs, req.GPUs, a.host.GPUCount,
			))
		}
		if req.GPUVendor != "" && a.host.GPUVendor != "" && req.GPUVendor != a.host.GPUVendor {
			reasons = append(reasons, fmt.Sprintf(
				"gpu vendor mismatch (requested %q, host has %q)",
				req.GPUVendor, a.host.GPUVendor,
			))
		}
	}

	if req.Runtime != "" && !a.runtimeSupported(req.Runtime) {
		reasons = append(reasons, fmt.Sprintf(
			"runtime %q not supported on this host (have %v)",
			req.Runtime, a.host.SupportedRuntimes,
		))
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

	// Phase 5: effective-memory watermark. Gated on a non-nil sampler
	// AND Ready() — a cold-start sampler returns 0, which under a
	// non-zero ratio would otherwise look like "host is empty" and
	// falsely admit. Pre-tick we fall through to nominal accounting.
	if watermark := a.rssWatermarkMB(); watermark > 0 && a.rss != nil && a.rss.Ready() {
		actual := a.rss.TotalRSSMB()
		effective := a.host.MemoryTotalMB - actual
		if effective-req.MemoryMB < watermark {
			reasons = append(reasons, fmt.Sprintf(
				"effective memory below rss watermark (effective=%d MB - req=%d MB < floor=%d MB)",
				effective, req.MemoryMB, watermark,
			))
		}
	}

	if len(reasons) > 0 {
		return fmt.Errorf("%w: %v", ErrCapacityExceeded, reasons)
	}

	if exists {
		a.totalCPU -= prior.CPU
		a.totalMemMB -= prior.MemoryMB
		a.totalDiskGB -= prior.DiskGB
		a.totalGPUs -= prior.GPUs
	}
	a.reservations[sandboxID] = req
	a.totalCPU += req.CPU
	a.totalMemMB += req.MemoryMB
	a.totalDiskGB += req.DiskGB
	a.totalGPUs += req.GPUs
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
	a.totalDiskGB -= prior.DiskGB
	a.totalGPUs -= prior.GPUs
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
		a.totalDiskGB -= prior.DiskGB
		a.totalGPUs -= prior.GPUs
	}
	a.reservations[sandboxID] = req
	a.totalCPU += req.CPU
	a.totalMemMB += req.MemoryMB
	a.totalDiskGB += req.DiskGB
	a.totalGPUs += req.GPUs
}

// Snapshot returns a point-in-time view. Includes a CanAdmit answer for a
// hypothetical zero-resource sandbox so operators can see "is this host
// accepting at all" without having to make a real request.
func (a *Admitter) Snapshot() Snapshot {
	a.mu.Lock()
	count := len(a.reservations)
	// Break the live count down by runtime for the per-isolation dashboard.
	// Cheap: one pass over the same reservations map we already sized above,
	// bounded by the handful of runtimes a host supports.
	byRuntime := make(map[string]int, len(a.host.SupportedRuntimes)+1)
	for _, req := range a.reservations {
		rt := req.Runtime
		if rt == "" {
			rt = "unspecified"
		}
		byRuntime[rt]++
	}
	totalCPU := a.totalCPU
	totalMem := a.totalMemMB
	totalDisk := a.totalDiskGB
	totalGPUs := a.totalGPUs
	a.mu.Unlock()

	free := 0
	if a.probe != nil {
		if v, err := a.probe.FreeMB(); err == nil {
			free = v
		}
	}
	diskFree := a.host.DiskFreeGB
	if _, v, err := detectDiskGB(defaultDiskPath()); err == nil {
		diskFree = v
	}

	// Phase 5: only surface RSS fields when a sampler is wired in and
	// has produced at least one observation. Reporting 0 on a host
	// without the axis would mislead placement on peers running the
	// new binary into thinking the old peer has zero RSS in use.
	var actualRSS, effectiveFree int
	if a.rss != nil && a.rss.Ready() {
		actualRSS = a.rss.TotalRSSMB()
		effectiveFree = max(a.host.MemoryTotalMB-actualRSS, 0)
	}

	snap := Snapshot{
		HostCPUCores:              a.host.CPUCores,
		HostMemoryTotalMB:         a.host.MemoryTotalMB,
		HostDiskTotalGB:           a.host.DiskTotalGB,
		HostDiskFreeGB:            diskFree,
		ReservedCPU:               totalCPU,
		ReservedMemoryMB:          totalMem,
		ReservedDiskGB:            totalDisk,
		ReservedGPUs:              totalGPUs,
		AvailableCPU:              maxFloat(a.cpuBudget()-totalCPU, 0),
		AvailableMemoryMB:         maxInt(a.memBudgetMB()-totalMem, 0),
		AvailableDiskGB:           maxInt(a.diskBudgetGB()-totalDisk, 0),
		AvailableGPUs:             maxInt(a.host.GPUCount-totalGPUs, 0),
		LiveMemoryFreeMB:          free,
		SandboxesActive:           count,
		SandboxesByRuntime:        byRuntime,
		CPUReservationRatio:       a.limits.CPUReservationRatio,
		MemoryReservationRatio:    a.limits.MemoryReservationRatio,
		DiskReservationRatio:      a.limits.DiskReservationRatio,
		MemoryFloorRatio:          a.limits.MemoryFloorRatio,
		CPUOverProvisionFactor:    a.cpuOverProvisionFactor(),
		MemoryOverProvisionFactor: a.memOverProvisionFactor(),
		MemoryFloorMB:             a.memoryFloorMB(),
		CPUBudget:                 a.cpuBudget(),
		MemoryBudgetMB:            a.memBudgetMB(),
		DiskBudgetGB:              a.diskBudgetGB(),
		GPUCount:                  a.host.GPUCount,
		GPUVendor:                 a.host.GPUVendor,
		SupportedRuntimes:         a.host.SupportedRuntimes,
		ActualRSSMB:               actualRSS,
		EffectiveMemoryFreeMB:     effectiveFree,
		RSSWatermarkMB:            a.rssWatermarkMB(),
		RSSWatermarkRatio:         a.limits.RSSWatermarkRatio,
	}
	// Use the smallest meaningful request (1 CPU, 1 MB) as the probe ask.
	// We don't use 0/0 because that bypasses every check and would always
	// report CanAdmit=true even when the host is full.
	snap.CanAdmit, snap.Reasons = a.dryRun(Request{CPU: 1, MemoryMB: 1})
	recordHostPressure(snap)
	return snap
}

// CanAdmitRequest is a non-mutating admission probe for a specific shape.
func (a *Admitter) CanAdmitRequest(req Request) (bool, []string) {
	return a.dryRun(req)
}

// dryRun is Admit's check-only path — it returns whether a request would be
// admitted right now and the reasons if not, without mutating state.
func (a *Admitter) dryRun(req Request) (bool, []string) {
	a.mu.Lock()
	totalCPU := a.totalCPU
	totalMem := a.totalMemMB
	totalDisk := a.totalDiskGB
	totalGPUs := a.totalGPUs
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
	if a.limits.DiskReservationRatio > 0 && a.host.DiskTotalGB > 0 {
		diskBudget := a.diskBudgetGB()
		if totalDisk+req.DiskGB > diskBudget {
			reasons = append(reasons, fmt.Sprintf("disk reservation exceeded (%d GB/%d GB)", totalDisk, diskBudget))
		}
	}
	if req.GPUs > 0 {
		if a.host.GPUCount <= 0 {
			reasons = append(reasons, "host has no GPUs")
		} else if totalGPUs+req.GPUs > a.host.GPUCount {
			reasons = append(reasons, fmt.Sprintf("gpu reservation exceeded (%d/%d)", totalGPUs, a.host.GPUCount))
		}
		if req.GPUVendor != "" && a.host.GPUVendor != "" && req.GPUVendor != a.host.GPUVendor {
			reasons = append(reasons, fmt.Sprintf("gpu vendor mismatch (%q vs %q)", req.GPUVendor, a.host.GPUVendor))
		}
	}
	if req.Runtime != "" && !a.runtimeSupported(req.Runtime) {
		reasons = append(reasons, fmt.Sprintf("runtime %q unsupported", req.Runtime))
	}
	if floor := a.memoryFloorMB(); floor > 0 && a.probe != nil {
		if free, err := a.probe.FreeMB(); err == nil && free-req.MemoryMB < floor {
			reasons = append(reasons, fmt.Sprintf("live memory floor breached (%d MB free, %d MB floor)", free, floor))
		}
	}
	if watermark := a.rssWatermarkMB(); watermark > 0 && a.rss != nil && a.rss.Ready() {
		effective := a.host.MemoryTotalMB - a.rss.TotalRSSMB()
		if effective-req.MemoryMB < watermark {
			reasons = append(reasons, fmt.Sprintf("effective memory below rss watermark (%d MB free, %d MB floor)", effective, watermark))
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

// rssWatermarkMB is the absolute "keep this much real RAM in reserve"
// floor derived from RSSWatermarkRatio and host memory. Returns 0 when
// disabled or unknown — the gate check on the call sites already treats
// 0 as "skip the check", so callers don't need a separate enable flag.
func (a *Admitter) rssWatermarkMB() int {
	if a.limits.RSSWatermarkRatio <= 0 || a.host.MemoryTotalMB <= 0 {
		return 0
	}
	return int(float64(a.host.MemoryTotalMB) * a.limits.RSSWatermarkRatio)
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

// diskBudgetGB is the post-ratio reservation ceiling for disk. Unlike
// CPU/memory there is no overcommit factor — disk allocations are real
// blocks Docker reserves via --storage-opt size; lying about headroom
// just trades a clean 503 for a noisy ENOSPC mid-write.
func (a *Admitter) diskBudgetGB() int {
	if a.limits.DiskReservationRatio <= 0 || a.host.DiskTotalGB <= 0 {
		return 0
	}
	return int(float64(a.host.DiskTotalGB) * a.limits.DiskReservationRatio)
}

// runtimeSupported reports whether the host advertises support for the named
// runtime. Empty SupportedRuntimes (legacy snapshot from a peer that pre-dates
// the field) is treated as "supports anything" so rolling upgrades don't
// strand pre-D peers from receiving placements.
func (a *Admitter) runtimeSupported(runtime string) bool {
	if len(a.host.SupportedRuntimes) == 0 {
		return true
	}
	for _, r := range a.host.SupportedRuntimes {
		if r == runtime {
			return true
		}
	}
	return false
}

func defaultDiskPath() string {
	if _, err := os.Stat("/var/lib/docker"); err == nil {
		return "/var/lib/docker"
	}
	return "/"
}

func detectDiskGB(path string) (int, int, error) {
	if path == "" {
		path = "/"
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0, fmt.Errorf("read host disk: %w", err)
	}
	blockSize := uint64(st.Bsize)
	total := bytesToGB(uint64(st.Blocks) * blockSize)
	free := bytesToGB(uint64(st.Bavail) * blockSize)
	return total, free, nil
}

func bytesToGB(bytes uint64) int {
	if bytes == 0 {
		return 0
	}
	const gib = uint64(1024 * 1024 * 1024)
	gb := bytes / gib
	if gb == 0 {
		return 1
	}
	return int(gb)
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}
