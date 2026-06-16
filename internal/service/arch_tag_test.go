package service

import (
	"runtime"
	"testing"
)

func TestArchTagSuffix(t *testing.T) {
	if got := archTagSuffix(snapshotArchAMD64); got != "" {
		t.Fatalf("amd64 suffix = %q, want empty", got)
	}
	if got := archTagSuffix(snapshotArchARM64); got != "--arch-arm64" {
		t.Fatalf("arm64 suffix = %q", got)
	}
}

func TestArchFromImageRef(t *testing.T) {
	cases := []struct {
		ref  string
		want string
	}{
		{"", snapshotArchAMD64},
		{"aocr.test/cluster/c1/snapshots/snap:latest", snapshotArchAMD64},
		{"aocr.test/cluster/c1/snapshots/snap:latest--ttl-1h", snapshotArchAMD64},
		{"aocr.test/cluster/c1/snapshots/snap:latest--arch-arm64", snapshotArchARM64},
		{"aocr.test/cluster/c1/snapshots/snap:latest--arch-arm64--ttl-1h", snapshotArchARM64},
		{"aocr.test/cluster/c1/snapshots/snap:latest--ttl-1h--arch-amd64", snapshotArchAMD64},
	}
	for _, tc := range cases {
		if got := archFromImageRef(tc.ref); got != tc.want {
			t.Fatalf("archFromImageRef(%q) = %q, want %q", tc.ref, got, tc.want)
		}
	}
}

func TestValidateSnapshotRefArch(t *testing.T) {
	host := hostSnapshotArch()
	foreign := snapshotArchAMD64
	if host == snapshotArchAMD64 {
		foreign = snapshotArchARM64
	}
	ref := "aocr.test/cluster/c1/snapshots/snap:latest--arch-" + foreign
	if err := ValidateSnapshotRefArch(ref, host); err == nil {
		t.Fatalf("expected rejection for foreign arch ref %q on host %q", ref, host)
	}
	sameRef := "aocr.test/cluster/c1/snapshots/snap:latest"
	if host == snapshotArchARM64 {
		sameRef += "--arch-arm64"
	}
	if err := ValidateSnapshotRefArch(sameRef, host); err != nil {
		t.Fatalf("same-arch ref should pass: %v", err)
	}
}

func TestClusterArtifactRefRequiresArchGuard(t *testing.T) {
	cases := []struct {
		ref  string
		want bool
	}{
		{"aocr.test/cluster/c1/snapshots/snap:latest", true},
		{"docker://aocr.test/cluster/c1/templates/tpl:latest", true},
		{"aocr.test/cluster/c1/_imported/ghcr/org/img:latest--idle-90d", false},
		{"aocr.test/team/app:latest", false},
		{"ubuntu:22.04", false},
	}
	for _, tc := range cases {
		if got := clusterArtifactRefRequiresArchGuard(tc.ref); got != tc.want {
			t.Fatalf("clusterArtifactRefRequiresArchGuard(%q) = %v, want %v", tc.ref, got, tc.want)
		}
	}
}

func TestValidateClusterArtifactRefArchSkipsImportedRefs(t *testing.T) {
	ref := "aocr.test/cluster/c1/_imported/ghcr/org/img:latest--idle-90d"
	if err := validateClusterArtifactRefArch(ref, snapshotArchARM64); err != nil {
		t.Fatalf("imported AOCR refs are not arch-specific firecracker artifacts: %v", err)
	}
}

func TestSnapshotAOCRRefIncludesHostArch(t *testing.T) {
	ref := snapshotAOCRRef("aocr.test", "cluster-1", "Snap", "")
	wantSuffix := archTagSuffix(hostSnapshotArch())
	if wantSuffix != "" && !containsSuffix(ref, wantSuffix) {
		t.Fatalf("snapshotAOCRRef = %q, want arch suffix %q", ref, wantSuffix)
	}
	if runtime.GOARCH == "amd64" && ref != "aocr.test/cluster/cluster-1/snapshots/snap:latest" {
		t.Fatalf("amd64 ref = %q", ref)
	}
}

func containsSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// testHostAOCRRef appends the host GOARCH tag suffix for tests that exercise
// push/pull paths or EnsureTemplateLocal arch guards.
func testHostAOCRRef(base string) string {
	return base + archTagSuffix(hostSnapshotArch())
}
