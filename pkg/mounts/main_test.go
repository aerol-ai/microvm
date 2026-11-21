package mounts

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain points the helpers' cgroup at a path that is not a cgroup, so no
// test ever creates or joins a cgroup on the host it runs on, even as root.
// Tests that need one stand in a directory (cgroup_test.go). Nor does any
// test remount a host path: adopting a kernel mount succeeds without one,
// and the tests that check the remount stand in their own.
func TestMain(m *testing.M) {
	helperCgroupRoot = filepath.Join(os.TempDir(), "aerolvm-mounts-test-no-cgroup")
	remountNosuidNodev = func(string) error { return nil }
	os.Exit(m.Run())
}
