package rootd

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

// scripts/install.sh --privilege-mode split --with-isolate
// --with-firecracker writes sandboxd.env, which the root helper reads too
// (aerolvm-rootd.service loads it before rootd.env). These run install.sh's
// own functions, the check of the flags and the env lines, on install.sh's
// own variables, and load what they print into the helper's ConfigFromEnv
// and into sandboxd's config.Load: the helper must start with both runtimes,
// and both sides must name the same jailer, firecracker, chroot base,
// kernel, jailer user and V8 jail.

const installShFromRootd = "../../scripts/install.sh"

// installShFuncs cuts install.sh's top-level functions names out of src: a
// function runs to the next top-level function definition (as
// internal/runtime/firecracker's install tests cut them).
func installShFuncs(t *testing.T, src string, names ...string) string {
	t.Helper()
	next := regexp.MustCompile(`\n[a-z_]+\(\) \{\n`)
	var out strings.Builder
	for _, name := range names {
		start := strings.Index(src, "\n"+name+"() {\n")
		if start < 0 {
			t.Fatalf("install.sh has no %s()", name)
		}
		body := src[start+1:]
		if loc := next.FindStringIndex(body[len(name)+5:]); loc != nil {
			body = body[:len(name)+5+loc[0]+1]
		}
		out.WriteString(body)
	}
	return out.String()
}

// installShSettings is install.sh's plain top-level settings, NAME="value"
// lines with nothing to expand, so the functions see the paths and names a
// real run has.
func installShSettings(src string) string {
	var out strings.Builder
	for _, l := range regexp.MustCompile(`(?m)^[A-Z][A-Z0-9_]*="[^"$`+"`"+`\\]*"$`).FindAllString(src, -1) {
		out.WriteString(l + "\n")
	}
	return out.String()
}

// splitInstallEnv runs check_privilege_mode, then prints sandboxd.env's
// split, Firecracker and V8 lines and rootd.env, as install.sh writes them
// for a split node with both runtimes. ids are the users install.sh makes.
// The second result is check_privilege_mode's refusal, if any.
func splitInstallEnv(t *testing.T) (map[string]string, string) {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	raw, err := os.ReadFile(installShFromRootd)
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	dir := t.TempDir()
	script := `set -euo pipefail
uname() { echo Linux; }
id() { case "$1 $2" in "-u sandboxd-jailer") echo 997 ;; "-g sandboxd-jailer") echo 996 ;;
	"-u sandboxd-isolate") echo 995 ;; "-g sandboxd-isolate") echo 994 ;; *) echo "id $*: no such user in this test" >&2; return 1 ;; esac; }
` + installShSettings(src) + installShFuncs(t, src, "flag_given", "check_privilege_mode", "split_environment",
		"firecracker_environment", "isolate_environment", "write_rootd_env") + `
PRIVILEGE_MODE=split WITH_CONTAINERD_ENGINE=true WITH_FIRECRACKER=true WITH_ISOLATE=true
CLI_ONLY=false LOCAL_MODE=false GIVEN_FLAGS=" --privilege-mode --with-containerd-engine --with-isolate --with-firecracker "
check_privilege_mode
ROOTD_ENV_FILE="` + filepath.Join(dir, "rootd.env") + `"
split_environment
firecracker_environment
isolate_environment
write_rootd_env
cat "$ROOTD_ENV_FILE"
`
	cmd := exec.Command(bash, "-c", script)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return nil, strings.TrimSpace(stderr.String()) + " (" + err.Error() + ")"
	}
	m := map[string]string{}
	for _, l := range strings.Split(stdout.String(), "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			t.Fatalf("install.sh printed a line that is no setting: %q", l)
		}
		m[k] = v
	}
	return m, ""
}

func TestInstallShSplitWithIsolatesAndFirecrackerLoadsIntoTheHelper(t *testing.T) {
	m, refused := splitInstallEnv(t)
	if refused != "" {
		t.Fatalf("install.sh refused --privilege-mode split with --with-isolate and --with-firecracker: %s", refused)
	}
	src, err := os.ReadFile(installShFromRootd)
	if err != nil {
		t.Fatal(err)
	}
	settings := installShSettings(string(src))
	value := func(name string) string {
		v := regexp.MustCompile(`(?m)^` + name + `="([^"]*)"$`).FindStringSubmatch(settings)
		if v == nil {
			t.Fatalf("install.sh has no %s", name)
		}
		return v[1]
	}
	for k, want := range map[string]string{
		"SB_PRIVILEGE_MODE":           "split",
		"SB_ENABLE_FIRECRACKER":       "true",
		"SB_FIRECRACKER_USE_JAILER":   "true",
		"SB_FIRECRACKER_KERNEL":       value("SPLIT_FIRECRACKER_KERNEL_PATH"),
		"SB_JAILER_CHROOT_BASE":       value("JAILER_CHROOT_BASE"),
		"SB_JAILER_BINARY":            value("JAILER_BIN"),
		"SB_FIRECRACKER_BINARY":       value("FIRECRACKER_BIN"),
		"SB_JAILER_UID":               "997",
		"SB_ISOLATE_USE_JAIL":         "true",
		"SB_ISOLATE_JAIL_UID":         "995",
		"SB_ISOLATE_JAIL_CHROOT_BASE": value("ISOLATE_JAIL_CHROOT_BASE"),
	} {
		if m[k] != want {
			t.Errorf("install.sh wrote %s=%q, want %q", k, m[k], want)
		}
	}
	// sandboxd.env does not name SB_ENABLE_ISOLATE through these functions
	// (write_environment writes it beside them); the helper needs it.
	m["SB_ENABLE_ISOLATE"] = "true"
	// The socket group and the mount tools' user by number: install.sh makes
	// them by name on the node, and this machine has neither.
	if m["SB_ROOTD_SOCKET_GROUP"] == "" || m["SB_ROOTD_MOUNT_USER"] == "" {
		t.Fatalf("rootd.env names no socket group or mount user: %v", m)
	}
	m["SB_ROOTD_SOCKET_GROUP"] = strconv.Itoa(os.Getgid())
	m["SB_ROOTD_MOUNT_USER"] = "64000:64000"

	stubHost(t, 8192, nil)
	old := selfExecutable
	selfExecutable = func() (string, error) { return "/usr/local/lib/aerolvm-rootd/aerolvm-rootd", nil }
	t.Cleanup(func() { selfExecutable = old })
	cfg, err := ConfigFromEnv(env(m))
	if err != nil {
		t.Fatalf("the helper refuses install.sh's split settings: %v", err)
	}
	fc, w := cfg.Hosts.Firecracker, cfg.Hosts.Workerd
	if fc == nil || w == nil {
		t.Fatalf("the helper runs Firecracker %v and V8 %v, want both", fc != nil, w != nil)
	}
	// Root runs each program at the path written, and the helper refuses a
	// link anywhere on it (checkRootBinaries): every one passes the path
	// rule the deploy tools share (CheckRootProgramPath), with sandboxd's
	// folders as install.sh lays them out.
	programs := RootPrograms(cfg)
	if len(programs) < 4 {
		t.Fatalf("the helper runs %v from install.sh's settings; want workerd, the jailer, firecracker and mkfs.ext4", programs)
	}
	agentDirs := []string{"/var/lib/sandboxd", "/run/sandboxd", "/run/aerolvm-procid", "/etc/sandboxd/tls", "/etc/sandboxd/cluster-ca"}
	for setting, p := range programs {
		if err := CheckRootProgramPath(p, agentDirs); err != nil {
			t.Errorf("install.sh's split settings: %s: %v", setting, err)
		}
	}

	// sandboxd reads the same lines.
	for k, v := range m {
		t.Setenv(k, v)
	}
	t.Setenv("SB_PAT_TOKEN", "pat-token")
	t.Setenv("SB_ENTERPRISE_MODE", "false")
	t.Setenv("SB_CONTAINER_ENGINE", "containerd")
	sb, err := config.Load()
	if err != nil {
		t.Fatalf("sandboxd refuses install.sh's split settings: %v", err)
	}
	if !sb.UseJailer || !sb.IsolateUseJail || sb.FirecrackerVMMPoolEnabled {
		t.Errorf("sandboxd: UseJailer %v, IsolateUseJail %v, VM pool %v; split needs true, true, false",
			sb.UseJailer, sb.IsolateUseJail, sb.FirecrackerVMMPoolEnabled)
	}
	for _, p := range []struct {
		what, helper, sandboxd string
	}{
		{"kernel", fc.Kernel, sb.FirecrackerKernelImage},
		{"jailer", fc.JailerBinary, sb.JailerBinary},
		{"firecracker", fc.FirecrackerBinary, sb.FirecrackerBinary},
		{"chroot base", fc.ChrootBase, sb.JailerChrootBase},
		{"jailer user", strconv.Itoa(fc.UID) + ":" + strconv.Itoa(fc.GID), strconv.Itoa(sb.JailerUID) + ":" + strconv.Itoa(sb.JailerGID)},
		{"V8 jail base", w.Jail.ChrootBase, sb.IsolateJailChrootBase},
		{"V8 jail user", strconv.Itoa(w.Jail.UID) + ":" + strconv.Itoa(w.Jail.GID), strconv.Itoa(sb.IsolateJailUID) + ":" + strconv.Itoa(sb.IsolateJailGID)},
		{"workerd", w.Jail.WorkerdPath, sb.IsolateWorkerdPath},
	} {
		if p.helper != p.sandboxd {
			t.Errorf("%s: the helper uses %q, sandboxd %q", p.what, p.helper, p.sandboxd)
		}
	}
	// The kernel is root's alone: not in sandboxd's data folder, which
	// sandboxd's user owns in split.
	if dataDir := filepath.Dir(sb.DBPath); strings.HasPrefix(fc.Kernel, dataDir+"/") {
		t.Errorf("kernel %s is in sandboxd's folder %s", fc.Kernel, dataDir)
	}
}
