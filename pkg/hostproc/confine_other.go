//go:build !linux

package hostproc

// Privilege drops and seccomp filters are Linux only. The callers never
// ask for them elsewhere: they confine only when sandboxd runs as root on
// Linux.

// DropPrivileges cannot drop off Linux.
func DropPrivileges(int, int) error { return ErrConfineUnsupported }

// InstallSeccomp cannot filter off Linux.
func InstallSeccomp([]SockFilter) error { return ErrConfineUnsupported }

// ConfinedProcFD is "" off Linux: there is no /proc/self/fd to reach a
// file through.
func ConfinedProcFD(uintptr) string { return "" }
