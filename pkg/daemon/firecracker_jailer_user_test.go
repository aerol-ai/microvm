package daemon

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

// fakeJailerUserFiles points the start check at a host where uid 1000 is a
// cloud image's login user (sudo, bash) and 996 is sandboxd-jailer.
func fakeJailerUserFiles(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	users, groups := filepath.Join(dir, "passwd"), filepath.Join(dir, "group")
	if err := os.WriteFile(users, []byte("root:x:0:0:root:/root:/bin/bash\n"+
		"ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n"+
		"sandboxd-jailer:x:996:996::/home/sandboxd-jailer:/usr/sbin/nologin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(groups, []byte("root:x:0:\nsudo:x:27:ubuntu\nubuntu:x:1000:\nsandboxd-jailer:x:996:\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := jailerUserFiles
	jailerUserFiles.users, jailerUserFiles.groups = users, groups
	t.Cleanup(func() { jailerUserFiles = old })
}

func TestCheckFirecrackerJailerUser(t *testing.T) {
	fakeJailerUserFiles(t)
	for _, tc := range []struct {
		name  string
		cfg   config.Config
		split bool
		want  string
	}{
		{name: "the jailer as sandboxd-jailer", cfg: config.Config{UseJailer: true, JailerUID: 996, JailerGID: 996}},
		{name: "no jailer: no user to check", cfg: config.Config{UseJailer: false, JailerUID: 1000, JailerGID: 1000}},
		{name: "the jailer as the login user", cfg: config.Config{UseJailer: true, JailerUID: 1000, JailerGID: 1000},
			want: "SB_JAILER_UID=1000 SB_JAILER_GID=1000: uid 1000 is the user ubuntu, in the sudo group"},
		// The root helper always runs the jailer, whatever sandboxd's setting.
		{name: "split checks even with the jailer setting off", cfg: config.Config{UseJailer: false, JailerUID: 1000, JailerGID: 1000},
			split: true, want: "the user ubuntu"},
		{name: "split as sandboxd-jailer", cfg: config.Config{JailerUID: 996, JailerGID: 996}, split: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := checkFirecrackerJailerUser(tc.cfg, tc.split)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want it to say %q", err, tc.want)
			}
		})
	}
}

// Run stops before any Firecracker work when the jailer's user is a login
// user, and says which setting to change and how.
func TestRun_FirecrackerRefusesAJailerLoginUser(t *testing.T) {
	paths := setBaseRunEnv(t)
	fakeJailerUserFiles(t)
	t.Setenv("SB_ENABLE_FIRECRACKER", "true")
	t.Setenv("SB_FIRECRACKER_BINARY", "/bin/true")
	t.Setenv("SB_JAILER_BINARY", "/bin/true")
	t.Setenv("SB_FIRECRACKER_KERNEL", paths.firecrackerKernel)
	t.Setenv("SB_FIRECRACKER_RUN_DIR", paths.firecrackerRunDir)
	t.Setenv("SB_FIRECRACKER_USE_JAILER", "true")
	t.Setenv("SB_JAILER_CHROOT_BASE", filepath.Join(paths.rootDir, "jailer"))
	t.Setenv("SB_JAILER_UID", "1000")
	t.Setenv("SB_JAILER_GID", "1000")
	// Bad enough to fail the next step: a refusal that let Run go on would
	// show up as this error instead.
	t.Setenv("SB_FIRECRACKER_TAP_BASE_CIDR", "172.19.0.0/30")
	t.Setenv("SB_FIRECRACKER_TAP_POOL_SIZE", "999999")
	t.Setenv("SB_FIRECRACKER_SKOPEO_BIN", "/bin/true")
	t.Setenv("SB_FIRECRACKER_UMOCI_BIN", "/bin/true")
	t.Setenv("SB_FIRECRACKER_MKFS_BIN", "/bin/true")

	err := Run(context.Background(), testLogger(), nil)
	if err == nil {
		t.Fatal("Run started Firecracker with the jailer as a login user")
	}
	for _, w := range []string{"SB_JAILER_UID=1000", "the user ubuntu, in the sudo group", "useradd --system"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("Run error %q\ndoes not say %q", err, w)
		}
	}
	if strings.Contains(err.Error(), "tap pool seed") {
		t.Error("Run went on to the TAP pool after refusing the jailer's user")
	}
}
