package mounts

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain points the helpers' cgroup at a path that is not a cgroup, so no
// test ever creates or joins a cgroup on the host it runs on, even as root.
// Tests that need one stand in a directory (cgroup_test.go).
func TestMain(m *testing.M) {
	helperCgroupRoot = filepath.Join(os.TempDir(), "aerolvm-mounts-test-no-cgroup")
	os.Exit(m.Run())
}
