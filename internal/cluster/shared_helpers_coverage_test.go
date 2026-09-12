package cluster

import (
	"github.com/aerol-ai/microvm/pkg/capacity"
)

func step3FatCapacity() capacity.Snapshot {
	return capacity.Snapshot{
		HostCPUCores: 16, HostMemoryTotalMB: 65536, HostDiskTotalGB: 1024,
		CPUBudget: 16, MemoryBudgetMB: 65536, DiskBudgetGB: 1024,
		AvailableCPU: 16, AvailableMemoryMB: 65536, AvailableDiskGB: 1024,
		CanAdmit: true,
	}
}

func fmtErr(v any) string {
	if v == nil {
		return ""
	}
	return v.(error).Error()
}
