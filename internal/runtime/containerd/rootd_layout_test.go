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
// Every file root opens because a container names it (host files, ready
// socket names, stdio FIFOs, runsc configs, the gVisor moves folder) is
// the helper's to make, in its own folders, outside every folder the agent
// can write: the agent owns those and can replace anything in them, a
// root-made folder included (review H2, plan T2). So the helper's policy
// accepts its own folders and refuses the files this driver still makes
// in its run dir; in split mode the driver uses the helper's files
// instead (task T4).
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
	// The helper links each ready socket from where this driver binds it.
	if hc.Files.AgentReady != cfg.ReadyDir {
		t.Fatalf("the helper links ready sockets from %s; the driver binds them in %s", hc.Files.AgentReady, cfg.ReadyDir)
	}
	if _, folder, ok := rootpolicy.BindRootFor(p, filepath.Join(sc.MountsRootPath, "sb-1", "0")); !ok || !folder {
		t.Errorf("the helper's bind roots %v do not hold the external mounts under %s", p.BindRoots, sc.MountsRootPath)
	}
	if !slices.Contains(p.BindFiles, cfg.ToolboxBinaryPath) {
		t.Errorf("bind files %v lack the toolbox %s", p.BindFiles, cfg.ToolboxBinaryPath)
	}

	agentDirs := []string{cfg.RunDir, filepath.Dir(sc.DBPath), sc.MountsRootPath, sc.MountsCredentialsRuntimeDir, cfg.ReadyDir}
	rootOpens := append([]string{p.MovesDir, p.FIFODir, filepath.Dir(hc.Socket), hc.Files.Hosts, hc.Files.Ready, hc.Files.Runsc}, p.RunscConfigPaths...)
	for _, r := range rootOpens {
		for _, a := range agentDirs {
			if r == a || strings.HasPrefix(r, a+"/") {
				t.Errorf("%s, which root opens, is inside %s, which the agent writes", r, a)
			}
		}
	}
	// The files this driver makes itself today: none passes the helper's
	// gate. Each has a helper call that makes it where the gate looks.
	for _, src := range []string{
		filepath.Join(hostFilesDir(cfg.RunDir, "sb-1"), "resolv.conf"),
		filepath.Join(cfg.ReadyDir, "sb-1.nonce.sock"),
		filepath.Join(cfg.ReadyDir, "park-1.sock"),
	} {
		if root, _, ok := rootpolicy.BindRootFor(p, src); ok {
			t.Errorf("the helper's policy binds the agent's own %s (from %s)", src, root)
		}
	}
	for _, rel := range []string{runscConfigRelPath, runscRestoreConfigRelPath, movesDirName} {
		if own := filepath.Join(cfg.RunDir, rel); slices.Contains(p.RunscConfigPaths, own) || own == p.MovesDir {
			t.Errorf("the helper trusts the agent's own %s", own)
		}
	}
	// The helper's own files pass, as files; its folders never do.
	for _, src := range []string{
		filepath.Join(hc.Files.Hosts, "sb-1", "resolv.conf"),
		filepath.Join(hc.Files.Ready, "sb-1", "0a1b.sock"),
		filepath.Join(hc.Files.Ready, "sb-1", "ready.sock"),
	} {
		if _, folder, ok := rootpolicy.BindRootFor(p, src); !ok || folder || rootpolicy.CheckBindSource(p, src) != nil {
			t.Errorf("the helper's policy refuses its own %s, or takes it for a folder", src)
		}
	}
	for _, src := range []string{filepath.Join(hc.Files.Hosts, "sb-1"), filepath.Join(hc.Files.Ready, "sb-1")} {
		if rootpolicy.CheckBindSource(p, src) == nil {
			t.Errorf("the helper's policy binds its own folder %s", src)
		}
	}
}
