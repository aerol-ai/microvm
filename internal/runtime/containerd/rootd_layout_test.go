package containerd

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// TestHelperPolicyMatchesDriverLayout: the root helper builds its policy
// from its own environment, with the setting names this driver's config
// reads (rootd.ConfigFromEnv). For the same settings it must allow the
// files this driver hands containerd: the hosts files, the ready socket,
// the toolbox, the gVisor moves folder and the runsc configs. A folder
// renamed here and not there would get every create refused once the
// agent runs without root.
func TestHelperPolicyMatchesDriverLayout(t *testing.T) {
	cfg := FromDaemonConfig(config.Config{
		ContainerdNamespace:         "tenant-a",
		ContainerdRunDir:            "/data/ctr",
		ContainerdCgroupParent:      "/aerolvm.slice",
		ToolboxBinaryPath:           "/opt/aerolvm/toolboxd",
		MountsCredentialsRuntimeDir: "/run/sbd",
	})
	env := map[string]string{
		"SB_CONTAINERD_NAMESPACE":     cfg.Namespace,
		"SB_CONTAINERD_RUN_DIR":       cfg.RunDir,
		"SB_CONTAINERD_CGROUP_PARENT": cfg.CgroupParent,
		"SB_TOOLBOX_BINARY_PATH":      cfg.ToolboxBinaryPath,
		"SB_MOUNTS_CRED_DIR":          "/run/sbd",
		"SB_ROOTD_SOCKET_GROUP":       strconv.Itoa(os.Getgid()),
		"SB_HOST_MEMORY_MB":           "1024",
	}
	hc, err := rootd.ConfigFromEnv(func(k string) string { return env[k] })
	if err != nil {
		t.Fatal(err)
	}
	p := hc.Policy
	if p.Namespace != cfg.Namespace || p.CgroupParent != cfg.CgroupParent {
		t.Fatalf("namespace %q, cgroup parent %q; the driver uses %q, %q", p.Namespace, p.CgroupParent, cfg.Namespace, cfg.CgroupParent)
	}
	for _, src := range []string{
		filepath.Join(hostFilesDir(cfg.RunDir, "sb-1"), "resolv.conf"),
		filepath.Join(cfg.ReadyDir, "sb-1.nonce.sock"),
	} {
		if _, ok := rootpolicy.BindRootFor(p, src); !ok {
			t.Errorf("the helper's bind roots %v do not hold %s", p.BindRoots, src)
		}
	}
	if !slices.Contains(p.BindFiles, cfg.ToolboxBinaryPath) {
		t.Errorf("bind files %v lack the toolbox %s", p.BindFiles, cfg.ToolboxBinaryPath)
	}
	if want := filepath.Join(cfg.RunDir, movesDirName); p.MovesDir != want {
		t.Errorf("moves dir %s, the driver's %s", p.MovesDir, want)
	}
	for _, rel := range []string{runscConfigRelPath, runscRestoreConfigRelPath} {
		if want := filepath.Join(cfg.RunDir, rel); !slices.Contains(p.RunscConfigPaths, want) {
			t.Errorf("runsc configs %v lack %s", p.RunscConfigPaths, want)
		}
	}
}
