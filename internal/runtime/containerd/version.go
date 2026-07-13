package containerd

import (
	"fmt"
	"strconv"
	"strings"
)

// Supported containerd daemon major versions (Phase 0(e-4)).
// Client is pinned in go.mod to the 1.7.x API; 2.x daemons speak a compatible
// gRPC surface for the subset we use. Reject anything older than 1.6 (shim v2
// / namespace semantics we rely on) or newer than 2.x until re-validated.
const (
	minContainerdMajor = 1
	minContainerdMinor = 6
	maxContainerdMajor = 2
)

func assertSupportedContainerdVersion(version string) error {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(version, "v")
	if version == "" {
		return fmt.Errorf("containerd version is empty")
	}
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return fmt.Errorf("containerd version %q: want major.minor", version)
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return fmt.Errorf("containerd version %q: bad major: %w", version, err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return fmt.Errorf("containerd version %q: bad minor: %w", version, err)
	}
	if major < minContainerdMajor || major > maxContainerdMajor {
		return fmt.Errorf("unsupported containerd major %d (supported %d–%d); got %s",
			major, minContainerdMajor, maxContainerdMajor, version)
	}
	if major == minContainerdMajor && minor < minContainerdMinor {
		return fmt.Errorf("unsupported containerd %s (need >= %d.%d)",
			version, minContainerdMajor, minContainerdMinor)
	}
	return nil
}
