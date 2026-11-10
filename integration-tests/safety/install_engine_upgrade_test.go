package safety

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestUpgradeContainerdEngineTools: a node the Terraform bootstrap set up
// runs the containerd engine without install.sh's --with-containerd-engine
// (the bootstrap installs CNI and BuildKit itself and writes the engine to
// cluster.env). A re-run of install.sh, the way every cluster moves to
// v0.7.0, must still move its CNI plugins and BuildKit to the pinned
// releases, and must leave a docker-engine node, or a node that has neither,
// alone.
func TestUpgradeContainerdEngineTools(t *testing.T) {
	src := installShSource(t)
	cniPin := installShVarSafety(t, src, "CNI_PLUGINS_VERSION")
	for _, tc := range []struct {
		name        string
		env         map[string]string // file in the env dir -> content
		cni         string            // version /opt/cni/bin/bridge reports; "" = no bridge
		cniDir      string            // where the bridge is, when not the default
		buildkitd   bool              // buildkitd in BUILDKIT_BIN_DIR
		want, never []string
	}{
		{name: "Terraform node, old CNI and BuildKit: both upgraded",
			env: map[string]string{"cluster.env": "SB_CONTAINER_ENGINE=containerd\n"}, cni: "v1.5.1", buildkitd: true,
			want: []string{"install_cni_plugins", "install_buildkit"}},
		{name: "Terraform node at the pinned CNI: BuildKit only checked",
			env: map[string]string{"cluster.env": "SB_CONTAINER_ENGINE=containerd\n"}, cni: cniPin, buildkitd: true,
			want: []string{"install_buildkit"}, never: []string{"install_cni_plugins"}},
		{name: "engine set in sandboxd.env, later line wins",
			env: map[string]string{"sandboxd.env": "SB_CONTAINER_ENGINE=docker\nSB_CONTAINER_ENGINE=containerd\n"}, cni: "v1.5.1",
			want: []string{"install_cni_plugins"}, never: []string{"install_buildkit"}},
		{name: "docker engine: nothing touched",
			env: map[string]string{"cluster.env": "SB_CONTAINER_ENGINE=docker\n"}, cni: "v1.5.1", buildkitd: true,
			never: []string{"install_cni_plugins", "install_buildkit"}},
		{name: "containerd engine, nothing installed yet: left for the bootstrap",
			env:   map[string]string{"cluster.env": "SB_CONTAINER_ENGINE=containerd\n"},
			never: []string{"install_cni_plugins", "install_buildkit"}},
		{name: "CNI in a custom directory: a warning, not a write",
			env: map[string]string{"cluster.env": "SB_CONTAINER_ENGINE=containerd\nSB_CONTAINERD_CNI_PLUGIN_DIR=__CUSTOM__\n"},
			cni: "v1.5.1", cniDir: "custom",
			want: []string{"warning: CNI plugins in"}, never: []string{"install_cni_plugins"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			envDir, bin := filepath.Join(dir, "env"), filepath.Join(dir, "bin")
			cniDir := "/opt/cni/bin"
			if tc.cniDir != "" {
				cniDir = filepath.Join(dir, tc.cniDir)
			}
			for _, d := range []string{envDir, bin} {
				mustMkdir(t, d)
			}
			for name, body := range tc.env {
				mustWrite(t, filepath.Join(envDir, name), strings.ReplaceAll(body, "__CUSTOM__", cniDir))
			}
			// The default CNI directory is a real path on this machine, so
			// the script reads a stand-in bridge through cni_version_at.
			bridgeVersion := ""
			if tc.cni != "" {
				bridgeVersion = tc.cni
				if tc.cniDir != "" {
					mustMkdir(t, cniDir)
					mustWrite(t, filepath.Join(cniDir, "bridge"), "#!/bin/sh\necho 'CNI bridge plugin "+tc.cni+"'\n")
					if err := os.Chmod(filepath.Join(cniDir, "bridge"), 0o755); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tc.buildkitd {
				mustWrite(t, filepath.Join(bin, "buildkitd"), "#!/bin/sh\n")
				if err := os.Chmod(filepath.Join(bin, "buildkitd"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			script := "set -euo pipefail\n" +
				"SANDBOXD_ENV_DIR='" + envDir + "'\nBUILDKIT_BIN_DIR='" + bin + "'\n" +
				"CNI_PLUGINS_VERSION='" + cniPin + "'\n" +
				extractShellFunc(t, src, "node_env_value") +
				extractShellFunc(t, src, "upgrade_containerd_engine_tools") +
				// Stand-ins: the real installs have their own tests.
				"install_cni_plugins() { echo install_cni_plugins; }\n" +
				"install_buildkit() { echo install_buildkit; }\n"
			if tc.cniDir == "" {
				// /opt/cni/bin is not ours to create here: answer for it.
				script += "cni_version_at() { echo '" + bridgeVersion + "'; }\n"
				if tc.cni != "" {
					script += "BRIDGE_STANDIN=1\n"
				}
			} else {
				script += extractShellFunc(t, src, "cni_version_at")
			}
			script += "upgrade_containerd_engine_tools 2>&1\necho DONE\n"
			if tc.cniDir == "" {
				// The function checks "-x <dir>/bridge" first; for the
				// default directory, make that test answer from the case.
				script = strings.Replace(script, `if [[ -x "${cni_dir}/bridge" ]]; then`,
					`if [[ -n "${BRIDGE_STANDIN:-}" ]]; then`, 1)
			}
			out, err := exec.Command("bash", "-c", script).CombinedOutput()
			if err != nil || !strings.Contains(string(out), "DONE") {
				t.Fatalf("upgrade_containerd_engine_tools: %v\n%s", err, out)
			}
			for _, w := range tc.want {
				if !strings.Contains(string(out), w) {
					t.Errorf("output lacks %q:\n%s", w, out)
				}
			}
			for _, n := range tc.never {
				if strings.Contains(string(out), n) {
					t.Errorf("output has %q:\n%s", n, out)
				}
			}
		})
	}
}
