//go:build !linux

package netrules

// newEnabledManager is a stub so the symbol resolves off Linux. NewWithOptions
// returns a disabled manager before calling it when GOOS != linux.
func newEnabledManager(backend, userChain string) (*Manager, error) {
	recordBackendSelected("disabled")
	return &Manager{enabled: false, userChain: userChain}, nil
}
