package containerd

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// TestHelperPolicyMatchesDriverLayout: the root helper builds its policy
// from its own environment, with the setting names this driver's config
// reads. One environment goes through both loaders here (sandboxd's
// config.Load and rootd.ConfigFromEnv), so a renamed setting on either
// side fails this test.
//
// For the files the agent fills and root only binds (hosts files, the
// ready socket, the toolbox), the helper must allow this driver's paths.
// For the files root reads or runs because the agent names them (the
// runsc configs, the gVisor moves folder), the helper's paths must be
// outside every folder the agent can write: the agent owns those and can
// replace anything in them, a root-made folder included (review H2).
func TestHelperPolicyMatchesDriverLayout(t *testing.T) {
	env := map[string]string{
		"SB_CONTAINERD_NAMESPACE":     "tenant-a",
		"SB_CONTAINERD_RUN_DIR":       "/data/ctr",
		"SB_CONTAINERD_CGROUP_PARENT": "/aerolvm.slice",
		"SB_TOOLBOX_BINARY_PATH":      "/opt/aerolvm/toolboxd",
		"SB_MOUNTS_CRED_DIR":          "/run/sbd",
		"SB_MOUNTS_ROOT":              "/data/mounts",
		"SB_DB_PATH":                  "/data/state/state.db",
		// sandboxd's loader needs a token to load at all, and the engine
		// for the containerd settings.
		"SB_PAT_TOKEN":        "layout-test-token-0123456789abcdef",
		"SB_CONTAINER_ENGINE": "containerd",
		// The helper's own settings.
		"SB_ROOTD_SOCKET_GROUP": strconv.Itoa(os.Getgid()),
		"SB_HOST_MEMORY_MB":     "1024",
	}
	for k, v := range env {
		t.Setenv(k, v)
	}
	sc, err := config.Load()
	if err != nil {
		t.Fatal(err)
	}
	cfg := FromDaemonConfig(sc)
	hc, err := rootd.ConfigFromEnv(os.Getenv)
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
		filepath.Join(sc.MountsRootPath, "sb-1", "0"),
	} {
		if _, ok := rootpolicy.BindRootFor(p, src); !ok {
			t.Errorf("the helper's bind roots %v do not hold %s", p.BindRoots, src)
		}
	}
	if !slices.Contains(p.BindFiles, cfg.ToolboxBinaryPath) {
		t.Errorf("bind files %v lack the toolbox %s", p.BindFiles, cfg.ToolboxBinaryPath)
	}

	agentDirs := []string{cfg.RunDir, filepath.Dir(sc.DBPath), sc.MountsRootPath, sc.MountsCredentialsRuntimeDir}
	rootReads := append([]string{p.MovesDir, p.FIFODir, filepath.Dir(hc.Socket)}, p.RunscConfigPaths...)
	for _, r := range rootReads {
		for _, a := range agentDirs {
			if r == a || strings.HasPrefix(r, a+"/") {
				t.Errorf("%s, which root reads, is inside %s, which the agent writes", r, a)
			}
		}
	}
	// The driver still writes its own runsc configs and moves folder in
	// its run dir. In split mode those names are refused until the agent
	// uses the helper's files (task T4); this pins where they are now.
	for _, rel := range []string{runscConfigRelPath, runscRestoreConfigRelPath, movesDirName} {
		if own := filepath.Join(cfg.RunDir, rel); slices.Contains(p.RunscConfigPaths, own) || own == p.MovesDir {
			t.Errorf("the helper trusts the agent's own %s", own)
		}
	}
}
