package caddy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runRig runs the real install.sh from the top to its end on a fake
// machine: every /etc, /var, /run and /srv path it writes moved under one
// temp dir, the root check reading a stand-in for $EUID, and the commands
// that change a real host (systemctl, apt-get, useradd) replaced by bash
// functions that log their arguments to $LOG. The install steps that need
// a real host (Docker, the mount tools, Caddy's package and its ELF check)
// are replaced the same way. curl and install run for real, through a
// logging wrapper, so file:// downloads and installs land in the temp dir.
//
// It is how --config-only and the upgrader hand-off are tested: what the
// script writes is in the temp dir, and what it does to the host is in the
// log.
type runRig struct {
	t      *testing.T
	bash   string
	dir    string
	script string
	log    string
}

func newRunRig(t *testing.T) *runRig {
	t.Helper()
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not found")
	}
	raw, err := os.ReadFile("../../scripts/install.sh")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// A systemd host has these before any install.
	if err := os.MkdirAll(filepath.Join(dir, "systemd", "system"), 0o755); err != nil {
		t.Fatal(err)
	}
	src := strings.NewReplacer(
		"/run/sandboxd-public", dir+"/run-public",
		"/etc/systemd", dir+"/systemd",
		"/etc/default/caddy", dir+"/default-caddy",
		"/etc/caddy", dir+"/caddy",
		"/etc/sandboxd", dir+"/sandboxd",
		"/var/lib/sandboxd", dir+"/varlib",
		"/run/sandboxd", dir+"/run",
		"/srv/isolate-jail", dir+"/srv-isolate",
		`CGROUP_ROOT="/sys/fs/cgroup"`, `CGROUP_ROOT="`+dir+`/cgroup"`,
		"SANDBOXD_READY_TRIES=60", "SANDBOXD_READY_TRIES=1",
		"$EUID", "$FAKE_EUID",
	).Replace(string(raw))

	stubs := `uname() { case "${1:-}" in -m) echo x86_64 ;; *) echo Linux ;; esac; }
hostname() { [[ "${1:-}" == -I ]] && echo '10.0.0.7'; }
systemctl() {
	echo "systemctl $*" >>"$LOG"
	case "$*" in
	"is-active --quiet sandboxd") [[ "${SANDBOXD_ACTIVE:-true}" == true ]] ;;
	"is-active --quiet "*) return 0 ;;
	esac
	return 0
}
apt-get() { echo "apt-get $*" >>"$LOG"; }
useradd() { echo "useradd $*" >>"$LOG"; }
id() { echo 990; }
getent() { return 0; }
resolvectl() { echo "Current Scopes: DNS"; }
sleep() { :; }
curl() { echo "curl $*" >>"$LOG"; command curl "$@"; }
install() { echo "install $*" >>"$LOG"; command install "$@"; }
`
	// After every function definition, before the main flow: the steps
	// that need a real host.
	overrides := `ensure_docker() { echo "ensure_docker" >>"$LOG"; }
install_mount_tools() { echo "install_mount_tools" >>"$LOG"; }
install_caddy_package() { echo "install_caddy_package" >>"$LOG"; }
drop_caddy_apt_source() { :; }
verify_custom_caddy_binary() { echo "verify_custom_caddy_binary $2" >>"$LOG"; }
`
	mainFlow := "\nif [[ \"$CONFIG_ONLY\" == \"true\" ]]; then\n\tif [[ $FAKE_EUID -ne 0 ]]; then\n"
	if strings.Count(src, mainFlow) != 1 {
		t.Fatal("install.sh's main flow no longer starts with the --config-only branch; update this rig")
	}
	src = strings.Replace(src, mainFlow, "\n"+overrides+mainFlow, 1)
	const head = "#!/usr/bin/env bash\n\nset -euo pipefail\n"
	if !strings.HasPrefix(src, head) {
		t.Fatalf("install.sh does not start with %q", head)
	}
	src = head + stubs + strings.TrimPrefix(src, head)
	path := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(path, []byte(src), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "usrbin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "usrbin", "caddy"), []byte(installedCaddy), 0o755); err != nil {
		t.Fatal(err)
	}
	return &runRig{t: t, bash: bash, dir: dir, script: path, log: filepath.Join(dir, "calls.log")}
}

// installedCaddy is the rig host's caddy binary.
const installedCaddy = "#!/bin/sh\necho the installed caddy\n"

func (r *runRig) path(rel string) string { return filepath.Join(r.dir, rel) }

func (r *runRig) env(extra ...string) []string {
	// The host's caddy is a file in the temp dir, first on PATH, so a step
	// that replaces it never reaches the real one.
	env := []string{"PATH=" + r.path("usrbin") + string(os.PathListSeparator) + os.Getenv("PATH")}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, "PATH=") {
			env = append(env, kv)
		}
	}
	env = append(env, "LOG="+r.log, "FAKE_EUID=0", "CAPTURE="+r.path("capture"))
	return append(env, extra...)
}

// run runs install.sh with args and env (KEY=value), from a directory with
// no go.mod so it never builds from source.
func (r *runRig) run(env []string, args ...string) (string, error) {
	r.t.Helper()
	cmd := exec.Command(r.bash, append([]string{r.script}, args...)...)
	cmd.Dir = r.t.TempDir()
	cmd.Env = env
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func (r *runRig) calls() string {
	b, _ := os.ReadFile(r.log)
	return string(b)
}

func (r *runRig) resetLog() { _ = os.Remove(r.log) }

func (r *runRig) write(rel, content string, mode os.FileMode) string {
	r.t.Helper()
	p := r.path(rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		r.t.Fatal(err)
	}
	return p
}

func (r *runRig) read(rel string) string {
	r.t.Helper()
	b, err := os.ReadFile(r.path(rel))
	if err != nil {
		r.t.Fatal(err)
	}
	return string(b)
}

func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
