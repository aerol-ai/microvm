package daemon

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// A Nitro worker pool (worker.firecracker.backend: nitro,
// plans/security-gaps-m1-m4.md §4.3): the preflight checks the Nitro
// device instead of /dev/kvm, the agent runs the Nitro backend from the
// image's Nitro folder and offers firecracker-nitro, and sandboxd takes the
// settings the chart renders. A KVM pool renders exactly as before.
func TestChartNitroWorkerPool(t *testing.T) {
	helm := chartHelm(t)
	fc := []string{"--set", "worker.firecracker.enabled=true"}
	for _, tc := range []struct {
		name      string
		flags     []string
		preflight string
		runtime   string
		env       map[string]string
		absent    []string
	}{
		{name: "kvm (the default)", flags: fc, preflight: "--kvm", runtime: models.RuntimeFirecracker,
			env:    map[string]string{"SB_FIRECRACKER_KERNEL": "/opt/aerolvm/firecracker/vmlinux"},
			absent: []string{"SB_FIRECRACKER_BACKEND", "SB_FIRECRACKER_NITRO_MODE", "SB_FIRECRACKER_BINARY", "SB_JAILER_BINARY"}},
		{name: "nitro", flags: append(fc, "--set", "worker.firecracker.backend=nitro"), preflight: "--nitro", runtime: models.RuntimeFirecrackerNitro,
			env: map[string]string{"SB_FIRECRACKER_BACKEND": "nitro", "SB_FIRECRACKER_NITRO_MODE": "direct",
				"SB_FIRECRACKER_BINARY": "/opt/aerolvm/firecracker-nitro/firecracker", "SB_JAILER_BINARY": "/opt/aerolvm/firecracker-nitro/jailer",
				"SB_FIRECRACKER_KERNEL": "/opt/aerolvm/firecracker-nitro/bzImage"}},
		{name: "nitro, confidential", flags: append(fc, "--set", "worker.firecracker.backend=nitro", "--set", "worker.firecracker.nitroMode=confidential"),
			preflight: "--nitro", runtime: models.RuntimeFirecrackerNitro, env: map[string]string{"SB_FIRECRACKER_NITRO_MODE": "confidential"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := renderChart(helm, tc.flags...)
			if err != nil {
				t.Fatal(err)
			}
			if want := fmt.Sprintf(`["sandboxd", "preflight", "--pod", "%s"]`, tc.preflight); !strings.Contains(out, want) {
				t.Fatalf("the preflight is not %s", want)
			}
			env := workerEnv(t, out, "agent")
			for k, v := range tc.env {
				if env[k] != v {
					t.Errorf("%s = %q, want %q", k, env[k], v)
				}
			}
			for _, k := range tc.absent {
				if _, ok := env[k]; ok {
					t.Errorf("a KVM pool renders %s=%q", k, env[k])
				}
			}
			runtimes := strings.Split(env["SB_HOST_RUNTIMES"], ",")
			other := models.RuntimeFirecrackerNitro
			if tc.runtime == other {
				other = models.RuntimeFirecracker
			}
			if !slices.Contains(runtimes, tc.runtime) || slices.Contains(runtimes, other) {
				t.Fatalf("SB_HOST_RUNTIMES = %v, want %s and not %s", runtimes, tc.runtime, other)
			}
			// sandboxd takes what the chart renders.
			t.Setenv("SB_PAT_TOKEN", "chart-test")
			for _, k := range []string{"SB_FIRECRACKER_BACKEND", "SB_FIRECRACKER_NITRO_MODE"} {
				t.Setenv(k, env[k])
			}
			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("sandboxd refuses the chart's settings: %v", err)
			}
			if got := cfg.FirecrackerRuntime(); got != tc.runtime {
				t.Fatalf("FirecrackerRuntime() = %q, want %q", got, tc.runtime)
			}
		})
	}
}

// A backend or a mode the chart does not know fails at helm install, not
// as a worker that restarts forever.
func TestChartRefusesAnUnknownFirecrackerBackend(t *testing.T) {
	helm := chartHelm(t)
	for flag, want := range map[string]string{
		"worker.firecracker.backend=xen":    `worker.firecracker.backend is kvm or nitro, got "xen"`,
		"worker.firecracker.nitroMode=half": `worker.firecracker.nitroMode is direct or confidential, got "half"`,
	} {
		if _, err := renderChart(helm, "--set", "worker.firecracker.enabled=true", "--set", flag); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", flag, err, want)
		}
	}
}
