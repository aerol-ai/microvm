package config

import (
	"strings"
	"testing"
)

// SB_FIRECRACKER_BACKEND and SB_FIRECRACKER_NITRO_MODE
// (plans/security-gaps-m1-m4.md §4.3): unset is today's KVM node; a value
// that is neither name stops the start; the Nitro backend is refused until
// its driver lands, so no node offers a runtime it cannot run.
func TestLoadFirecrackerBackend(t *testing.T) {
	for _, tc := range []struct {
		name, backend, mode   string
		wantBackend, wantMode string
		wantErr               string
	}{
		{name: "unset is kvm, direct", wantBackend: "kvm", wantMode: "direct"},
		{name: "kvm spelled out", backend: " KVM ", wantBackend: "kvm", wantMode: "direct"},
		{name: "confidential on a kvm node is read and ignored", backend: "kvm", mode: "Confidential", wantBackend: "kvm", wantMode: "confidential"},
		{name: "nitro is not in this build", backend: "nitro", wantErr: "not in this build yet"},
		{name: "an unknown backend", backend: "xen", wantErr: "SB_FIRECRACKER_BACKEND"},
		{name: "an unknown mode", mode: "half", wantErr: "SB_FIRECRACKER_NITRO_MODE"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			t.Setenv("SB_FIRECRACKER_BACKEND", tc.backend)
			t.Setenv("SB_FIRECRACKER_NITRO_MODE", tc.mode)
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want one naming %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load() error = %v", err)
			}
			if cfg.FirecrackerBackend != tc.wantBackend || cfg.FirecrackerNitroMode != tc.wantMode {
				t.Fatalf("backend %q mode %q, want %q %q", cfg.FirecrackerBackend, cfg.FirecrackerNitroMode, tc.wantBackend, tc.wantMode)
			}
		})
	}
}

// The Nitro runtime cannot be the host default, as firecracker cannot: a
// create with no runtime must never land on a VM backend by surprise.
func TestLoadRefusesFirecrackerNitroAsHostDefault(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "operator-pat")
	t.Setenv("SB_CONTAINER_RUNTIME", "firecracker-nitro")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "not allowed as the host default") {
		t.Fatalf("err = %v", err)
	}
}
