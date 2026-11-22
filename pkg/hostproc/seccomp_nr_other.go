//go:build !linux || (!amd64 && !arm64)

package hostproc

// Seccomp filters are installed on Linux amd64/arm64 only; elsewhere there
// is no syscall table and no arch, and the callers refuse a filter they
// were asked for.

// SeccompArch is 0: no architecture to check.
func SeccompArch() uint32 { return 0 }

// SyscallTable is nil: no syscall numbers.
func SyscallTable() map[string]int { return nil }
