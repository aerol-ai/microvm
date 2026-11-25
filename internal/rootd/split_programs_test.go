package rootd

import (
	"maps"
	"os"
	"strconv"
	"strings"
	"testing"
)

// splitProgramsFile lists the program paths each deploy tool gives the
// helper for split (testdata/split_programs.txt).
const splitProgramsFile = "testdata/split_programs.txt"

// splitPrograms reads splitProgramsFile: tool -> setting -> path.
func splitPrograms(t testing.TB) map[string]map[string]string {
	t.Helper()
	raw, err := os.ReadFile(splitProgramsFile)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]string{}
	for i, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if len(f) != 3 {
			t.Fatalf("%s:%d: want tool, setting, path: %q", splitProgramsFile, i+1, line)
		}
		if out[f[0]] == nil {
			out[f[0]] = map[string]string{}
		}
		out[f[0]][f[1]] = f[2]
	}
	return out
}

// TestHelperDefaultProgramsAreListed: with every runtime and gVisor moves
// on and no program named, the helper runs its own defaults, and those are
// what splitProgramsFile lists for "helper", which
// TestRootProgramsOnThisHostsLayout checks on real hosts. Each passes the
// path rule.
func TestHelperDefaultProgramsAreListed(t *testing.T) {
	stubHost(t, 8192, nil)
	old := selfExecutable
	selfExecutable = func() (string, error) { return "/usr/local/lib/aerolvm-rootd/aerolvm-rootd", nil }
	t.Cleanup(func() { selfExecutable = old })
	cfg, err := ConfigFromEnv(env(map[string]string{"SB_ROOTD_SOCKET_GROUP": strconv.Itoa(os.Getgid()),
		"SB_ENABLE_ISOLATE": "true", "SB_ENABLE_FIRECRACKER": "true", "SB_GVISOR_CHECKPOINT_MOVES": "true",
		"SB_FIRECRACKER_KERNEL": "/usr/local/lib/aerolvm-firecracker/vmlinux", "SB_JAILER_UID": "997", "SB_JAILER_GID": "997"}))
	if err != nil {
		t.Fatalf("the helper refuses its own defaults: %v", err)
	}
	got, want := RootPrograms(cfg), splitPrograms(t)["helper"]
	if !maps.Equal(got, want) {
		t.Fatalf("the helper's default programs are %v; %s lists %v", got, splitProgramsFile, want)
	}
	for k, p := range got {
		if err := CheckRootProgramPath(p, cfg.AgentDirs); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
}
