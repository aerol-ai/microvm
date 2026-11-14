//go:build !linux

package cluster

// syncFilesystem has no syncfs(2) to call off Linux: the store syncs each
// blob instead (fsyncEach).
func syncFilesystem(string) (bool, error) { return false, nil }
