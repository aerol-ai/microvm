package service

import (
	"fmt"
	"runtime"
	"strings"
)

const (
	snapshotArchAMD64 = "amd64"
	snapshotArchARM64 = "arm64"
	archTagMarker     = "--arch-"
)

// hostSnapshotArch returns the CPU architecture tag embedded in AOCR snapshot
// and template refs pushed from this process. Untagged refs imply amd64 for
// back-compat with snapshots pushed before arch tagging landed.
func hostSnapshotArch() string {
	switch runtime.GOARCH {
	case "arm64":
		return snapshotArchARM64
	default:
		return snapshotArchAMD64
	}
}

// archTagSuffix returns the AOCR tag suffix for arch (empty on amd64).
func archTagSuffix(arch string) string {
	arch = strings.TrimSpace(arch)
	if arch == "" || arch == snapshotArchAMD64 {
		return ""
	}
	return archTagMarker + arch
}

func clusterArtifactRefRequiresArchGuard(ref string) bool {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return false
	}
	if _, after, ok := strings.Cut(ref, "://"); ok {
		ref = after
	}
	firstSlash := strings.Index(ref, "/")
	if firstSlash < 0 {
		return false
	}
	segments := strings.Split(ref[firstSlash+1:], "/")
	return len(segments) >= 4 && segments[0] == "cluster" && (segments[2] == "snapshots" || segments[2] == "templates")
}

func validateClusterArtifactRefArch(ref, hostArch string) error {
	if !clusterArtifactRefRequiresArchGuard(ref) {
		return nil
	}
	return ValidateSnapshotRefArch(ref, hostArch)
}

// archFromImageRef parses the --arch-<goarch> suffix from a registry ref tag.
// Refs without an arch suffix are treated as amd64 (legacy x86 snapshots).
func archFromImageRef(ref string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return snapshotArchAMD64
	}
	tag := ref
	if i := strings.LastIndex(ref, ":"); i >= 0 {
		tag = ref[i+1:]
	}
	for _, part := range strings.Split(tag, "--") {
		if arch, ok := strings.CutPrefix(part, "arch-"); ok {
			return strings.TrimSpace(arch)
		}
	}
	return snapshotArchAMD64
}

// ValidateSnapshotRefArch rejects foreign-arch AOCR refs at resume/pull time.
// Defense-in-depth for homogeneous per-arch clusters (see plans/arm64-firecracker-hosts.md D5).
func ValidateSnapshotRefArch(ref, hostArch string) error {
	refArch := archFromImageRef(ref)
	hostArch = strings.TrimSpace(hostArch)
	if hostArch == "" {
		hostArch = hostSnapshotArch()
	}
	if refArch == hostArch {
		return nil
	}
	return fmt.Errorf("snapshot architecture %q does not match host architecture %q", refArch, hostArch)
}
