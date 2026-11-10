package caddy

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/nodeupgrade"
)

// installedNode writes what a full install left: node.json, sandboxd.env
// with the PAT, and the binaries in the install prefix.
func installedNode(r *runRig, nodeJSON string) {
	r.t.Helper()
	r.write("sandboxd/node.json", nodeJSON, 0o600)
	r.write("sandboxd/sandboxd.env", "SB_PAT_TOKEN=kept-pat\nSB_NODE_NAME=old\n", 0o600)
	r.write("bin/sandboxd", "the installed sandboxd\n", 0o755)
	r.write("bin/toolboxd", "the installed toolboxd\n", 0o755)
}

// hostEffects are the log lines --config-only must never produce: no
// download, no package, no binary replaced, no service started, stopped or
// restarted.
var hostEffects = regexp.MustCompile(`(?m)^(curl |apt-get |install -m|ensure_docker|install_mount_tools|install_caddy_package|verify_custom_caddy_binary|systemctl (start|stop|restart|enable|disable|reset-failed) )`)

// install.sh --config-only (plans/kubectl-style-cluster-ops.md §6.3 step 7):
// it re-renders every configuration file from node.json and the saved
// secrets and does nothing else to the host.
func TestInstallConfigOnlyRendersConfigAndTouchesNothingElse(t *testing.T) {
	cases := []struct {
		name      string
		nodeJSON  string
		wantFiles map[string][]string // rendered file → lines it must hold
		noFiles   []string
		wantOut   string
	}{
		{
			name: "IP mode with ingress routing",
			nodeJSON: `{
  "format": 1,
  "public_host": "203.0.113.9",
  "node_name": "edge-1",
  "install_prefix": "PREFIX",
  "ingress_proxy_routing": true,
  "with_gvisor": true
}`,
			wantFiles: map[string][]string{
				"sandboxd/sandboxd.env":                         {"SB_PAT_TOKEN=kept-pat", "SB_NODE_NAME=edge-1", "SB_PUBLIC_HOST=203.0.113.9", "SB_API_HOST=0.0.0.0", "SB_HOST_RUNTIMES=docker,gvisor", "SB_INGRESS_PROXY_ROUTING=true"},
				"caddy/Caddyfile":                               {":80 {"},
				"systemd/system/sandboxd.service":               {"ExecStart=PREFIX/sandboxd"},
				"systemd/system/aerolvm-egress-gateway.service": {"ExecStart=PREFIX/sandboxd egress-gateway"},
				"systemd/system/sandboxd-healthcheck.timer":     {"OnUnitActiveSec=30s"},
				"systemd/network/10-aerolvm-rt.network":         {"Domains=~rt.internal"},
				"sandboxd/node.json":                            {`"node_name": "edge-1"`, `"with_gvisor": true`},
			},
			wantOut: "the aerolvm-rt network units changed",
		},
		{
			name: "local mode",
			nodeJSON: `{
  "format": 1,
  "local": true,
  "install_prefix": "PREFIX",
  "idle_timeout_min": "15"
}`,
			wantFiles: map[string][]string{
				"sandboxd/sandboxd.env":           {"SB_PAT_TOKEN=kept-pat", "SB_API_HOST=127.0.0.1", "SB_IDLE_TIMEOUT_MIN=15", "SB_ENABLE_CADDY=false"},
				"systemd/system/sandboxd.service": {"Description=AerolVM daemon (local)", "ExecStart=PREFIX/sandboxd"},
			},
			noFiles: []string{"caddy/Caddyfile"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRunRig(t)
			prefix := r.path("bin")
			installedNode(r, strings.ReplaceAll(tc.nodeJSON, "PREFIX", prefix))
			out, err := r.run(r.env(), "--config-only")
			if err != nil {
				t.Fatalf("install.sh --config-only: %v\n%s", err, out)
			}
			for rel, lines := range tc.wantFiles {
				got := r.read(rel)
				for _, line := range lines {
					line = strings.ReplaceAll(line, "PREFIX", prefix)
					if !strings.Contains(got, line+"\n") && !strings.Contains(got, line) {
						t.Errorf("%s has no %q:\n%s", rel, line, got)
					}
				}
			}
			for _, rel := range tc.noFiles {
				if _, err := os.Stat(r.path(rel)); err == nil {
					t.Errorf("%s was written", rel)
				}
			}
			calls := r.calls()
			if m := hostEffects.FindString(calls); m != "" {
				t.Fatalf("--config-only did %q to the host; calls:\n%s", m, calls)
			}
			if !strings.Contains(calls, "systemctl daemon-reload\n") {
				t.Fatalf("--config-only did not reload the units; calls:\n%s", calls)
			}
			for bin, want := range map[string]string{"bin/sandboxd": "the installed sandboxd\n", "bin/toolboxd": "the installed toolboxd\n"} {
				if got := r.read(bin); got != want {
					t.Fatalf("%s was replaced: %q", bin, got)
				}
			}
			if tc.wantOut != "" && !strings.Contains(out, tc.wantOut) {
				t.Fatalf("output has no %q:\n%s", tc.wantOut, out)
			}
			if !strings.Contains(out, "no binary or service was touched") {
				t.Fatalf("output:\n%s", out)
			}
		})
	}
}

// --config-only re-renders a node that exists, as root, and never makes up
// a PAT.
func TestInstallConfigOnlyRefusals(t *testing.T) {
	cases := []struct {
		name  string
		setup func(r *runRig)
		args  []string
		env   []string
		want  string
	}{
		{name: "nothing installed", setup: func(*runRig) {}, want: "Run install.sh without it first"},
		{name: "no saved PAT", setup: func(r *runRig) {
			r.write("sandboxd/node.json", "{\n  \"format\": 1\n}\n", 0o600)
		}, want: "never makes a new one"},
		{name: "with --cli-only", setup: func(r *runRig) {
			installedNode(r, "{\n  \"format\": 1\n}\n")
		}, args: []string{"--cli-only"}, want: "does not work with --cli-only"},
		{name: "not root", setup: func(r *runRig) {
			installedNode(r, "{\n  \"format\": 1,\n  \"install_prefix\": \""+r.path("bin")+"\"\n}\n")
		}, env: []string{"FAKE_EUID=1000"}, want: "--config-only must run as root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRunRig(t)
			tc.setup(r)
			out, err := r.run(r.env(tc.env...), append([]string{"--config-only"}, tc.args...)...)
			if err == nil || !strings.Contains(out, tc.want) {
				t.Fatalf("err = %v, want %q in:\n%s", err, tc.want, out)
			}
			if _, err := os.Stat(r.path("sandboxd/sandboxd.env.new")); err == nil {
				t.Fatal("wrote a file")
			}
			if m := hostEffects.FindString(r.calls()); m != "" {
				t.Fatalf("a refused run did %q", m)
			}
		})
	}
}

// `sandboxd host apply` end to end: nodeupgrade.HostApply runs this
// install.sh with --config-only and node.json's settings as separate
// arguments, including a value with spaces and shell syntax, and the
// rendered env file carries it exactly.
func TestHostApplyRunsInstallShConfigOnly(t *testing.T) {
	r := newRunRig(t)
	prefix := r.path("bin")
	installedNode(r, `{
  "format": 1,
  "public_host": "203.0.113.9",
  "node_name": "edge 1 $(touch PWNED)",
  "install_prefix": "`+prefix+`"
}`)
	script, err := os.ReadFile(r.script)
	if err != nil {
		t.Fatal(err)
	}
	for _, kv := range r.env() {
		k, v, _ := strings.Cut(kv, "=")
		if k == "LOG" || k == "FAKE_EUID" || k == "CAPTURE" {
			t.Setenv(k, v)
		}
	}
	state := r.path("varlib/upgrade")
	var out strings.Builder
	err = nodeupgrade.HostApply(context.Background(), nodeupgrade.HostApplyOptions{
		Script: script, NodeJSON: r.path("sandboxd/node.json"), StateDir: state,
		Host: &nodeupgrade.SystemHost{}, Out: &out,
	})
	if err != nil {
		t.Fatalf("host apply: %v\n%s", err, out.String())
	}
	env := r.read("sandboxd/sandboxd.env")
	if !strings.Contains(env, "SB_NODE_NAME=edge 1 $(touch PWNED)\n") || !strings.Contains(env, "SB_PAT_TOKEN=kept-pat\n") {
		t.Fatalf("sandboxd.env:\n%s", env)
	}
	matches, _ := filepath.Glob(filepath.Join(r.dir, "*PWNED*"))
	if _, err := os.Stat("PWNED"); err == nil || len(matches) > 0 {
		t.Fatal("a node.json value ran as a command")
	}
	if m := hostEffects.FindString(r.calls()); m != "" {
		t.Fatalf("host apply did %q to the host", m)
	}
	if nodeupgrade.InstalledHostSetup(state, "") != sha256Hex(script) {
		t.Fatal("host apply did not record the script it applied")
	}
}
