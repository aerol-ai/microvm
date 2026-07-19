package capacity

import (
	"expvar"
	"sync"

	"github.com/aerol-ai/microvm/internal/scaleobs"
)

var (
	hostPressureSandboxes      = expvar.NewInt("aerolvm_host_pressure_sandboxes")
	hostPressureReservedCPU    = expvar.NewInt("aerolvm_host_pressure_reserved_cpu_millicores")
	hostPressureCPUBudget      = expvar.NewInt("aerolvm_host_pressure_cpu_budget_millicores")
	hostPressureReservedMemory = expvar.NewInt("aerolvm_host_pressure_reserved_memory_mb")
	hostPressureMemoryBudget   = expvar.NewInt("aerolvm_host_pressure_memory_budget_mb")
	hostPressureLiveMemoryFree = expvar.NewInt("aerolvm_host_pressure_live_memory_free_mb")
	hostPressureReservedDisk   = expvar.NewInt("aerolvm_host_pressure_reserved_disk_gb")
	hostPressureDiskBudget     = expvar.NewInt("aerolvm_host_pressure_disk_budget_gb")
	hostPressureReservedGPUs   = expvar.NewInt("aerolvm_host_pressure_reserved_gpus")
	hostPressureGPUCount       = expvar.NewInt("aerolvm_host_pressure_gpu_count")
	hostPressureCanAdmit       = expvar.NewInt("aerolvm_host_pressure_can_admit")
	hostPressureRejectReasons  = expvar.NewMap("aerolvm_host_pressure_reject_reasons")
	hostPressureReasonKeysMu   sync.Mutex
	hostPressureReasonKeys     = make(map[string]struct{})
	// aerolvm_sandboxes_by_runtime{key="docker|gvisor|wasm|isolate|firecracker"}
	// — live sandbox count per isolation type (the bare host_pressure_sandboxes
	// gauge has no runtime label). Stale runtimes are deleted so a runtime that
	// drops to zero doesn't linger at its old value.
	sandboxesByRuntime       = expvar.NewMap("aerolvm_sandboxes_by_runtime")
	sandboxesByRuntimeKeysMu sync.Mutex
	sandboxesByRuntimeKeys   = make(map[string]struct{})
	// Phase 5 effective-memory axis. Three gauges so dashboards can
	// plot "real RSS in use", "headroom we'd admit against", and "the
	// floor we refuse below". Zero on hosts without a sampler (the
	// default) — the watermark gauge stays at 0 so an alert "RSS within
	// 10% of watermark" doesn't fire on docker-only hosts.
	hostPressureActualRSS           = expvar.NewInt("aerolvm_host_pressure_actual_rss_mb")
	hostPressureEffectiveMemoryFree = expvar.NewInt("aerolvm_host_pressure_effective_memory_free_mb")
	hostPressureRSSWatermark        = expvar.NewInt("aerolvm_host_pressure_rss_watermark_mb")
)

func recordHostPressure(s Snapshot) {
	hostPressureSandboxes.Set(int64(s.SandboxesActive))
	hostPressureReservedCPU.Set(millicores(s.ReservedCPU))
	hostPressureCPUBudget.Set(millicores(s.CPUBudget))
	hostPressureReservedMemory.Set(int64(s.ReservedMemoryMB))
	hostPressureMemoryBudget.Set(int64(s.MemoryBudgetMB))
	hostPressureLiveMemoryFree.Set(int64(s.LiveMemoryFreeMB))
	hostPressureReservedDisk.Set(int64(s.ReservedDiskGB))
	hostPressureDiskBudget.Set(int64(s.DiskBudgetGB))
	hostPressureReservedGPUs.Set(int64(s.ReservedGPUs))
	hostPressureGPUCount.Set(int64(s.GPUCount))
	hostPressureActualRSS.Set(int64(s.ActualRSSMB))
	hostPressureEffectiveMemoryFree.Set(int64(s.EffectiveMemoryFreeMB))
	hostPressureRSSWatermark.Set(int64(s.RSSWatermarkMB))
	if s.CanAdmit {
		hostPressureCanAdmit.Set(1)
	} else {
		hostPressureCanAdmit.Set(0)
	}
	recordHostPressureReasons(s.Reasons)
	recordSandboxesByRuntime(s.SandboxesByRuntime)
}

func recordSandboxesByRuntime(byRuntime map[string]int) {
	sandboxesByRuntimeKeysMu.Lock()
	defer sandboxesByRuntimeKeysMu.Unlock()
	next := make(map[string]struct{}, len(byRuntime))
	for runtime, n := range byRuntime {
		key := scaleobs.Key(runtime)
		next[key] = struct{}{}
		v := new(expvar.Int)
		v.Set(int64(n))
		sandboxesByRuntime.Set(key, v)
	}
	for key := range sandboxesByRuntimeKeys {
		if _, ok := next[key]; !ok {
			sandboxesByRuntime.Delete(key)
		}
	}
	sandboxesByRuntimeKeys = next
}

func recordHostPressureReasons(reasons []string) {
	hostPressureReasonKeysMu.Lock()
	defer hostPressureReasonKeysMu.Unlock()
	next := make(map[string]struct{}, len(reasons))
	for _, reason := range reasons {
		key := scaleobs.Key(reason)
		next[key] = struct{}{}
		v := new(expvar.Int)
		v.Set(1)
		hostPressureRejectReasons.Set(key, v)
	}
	for key := range hostPressureReasonKeys {
		if _, ok := next[key]; !ok {
			hostPressureRejectReasons.Delete(key)
		}
	}
	hostPressureReasonKeys = next
}

func millicores(v float64) int64 {
	return int64(v * 1000)
}
