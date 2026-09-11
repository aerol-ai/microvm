//go:build !linux || (!amd64 && !arm64)

package isolate

// The jail is realized on Linux amd64/arm64 only; elsewhere there is no
// syscall table and no arch, and applyJail refuses to run a required jail.
func seccompAuditArch() uint32 { return 0 }

func seccompSyscallTable() map[string]int { return nil }
