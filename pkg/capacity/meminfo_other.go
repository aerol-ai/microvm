//go:build !linux

package capacity

import "errors"

// On non-Linux dev environments (e.g. macOS), /proc/meminfo isn't available.
// The probe returns an error so the admitter falls back to its "probe error
// = unknown, allow" behavior, which keeps unit tests and local dev runnable.
type unsupportedMemProbe struct{}

func NewProcMeminfoProbe() MemProbe { return unsupportedMemProbe{} }

func (unsupportedMemProbe) FreeMB() (int, error) {
	return 0, errors.New("meminfo probe not supported on this platform")
}

// totalMemoryMB is consumed by DetectHost in capacity.go. On non-Linux we
// can't reliably detect host memory; callers should override the field.
func totalMemoryMB() (int, error) {
	return 0, errors.New("host memory detection not supported on this platform")
}
