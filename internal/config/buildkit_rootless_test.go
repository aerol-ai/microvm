package config

import (
	"strings"
	"testing"
)

// SB_CONTAINERD_BUILDKIT_ROOTLESS (plans/security-gaps-m1-m4.md PR 10b, eng
// review D14): absent follows the privilege mode, so single keeps today's
// root buildkitd (D22) and split builds only through rootless BuildKit; set,
// it opts single in; split can never turn it off. A rootless node without
// SB_CONTAINERD_BUILDKIT_ADDR talks to install.sh's rootless socket.
func TestLoadBuildKitRootless(t *testing.T) {
	const rootAddr = "unix:///run/buildkit/buildkitd.sock"
	for _, tc := range []struct {
		name, mode, raw, addr string
		want                  bool
		wantAddr              string
	}{
		{name: "single, unset: today's root buildkitd", want: false, wantAddr: rootAddr},
		{name: "split, unset: rootless", mode: "split", want: true, wantAddr: DefaultBuildKitRootlessAddr},
		{name: "single opts in", raw: "true", want: true, wantAddr: DefaultBuildKitRootlessAddr},
		{name: "single, explicit off", mode: "single", raw: "false", want: false, wantAddr: rootAddr},
		{name: "split, explicit on", mode: "split", raw: " TRUE ", want: true, wantAddr: DefaultBuildKitRootlessAddr},
		{name: "an operator's socket is kept", raw: "1", addr: "unix:///srv/bk.sock", want: true, wantAddr: "unix:///srv/bk.sock"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			t.Setenv("SB_PRIVILEGE_MODE", tc.mode)
			t.Setenv("SB_CONTAINERD_BUILDKIT_ROOTLESS", tc.raw)
			t.Setenv("SB_CONTAINERD_BUILDKIT_ADDR", tc.addr)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.ContainerdBuildKitRootless != tc.want || cfg.ContainerdBuildKitAddr != tc.wantAddr {
				t.Fatalf("rootless %v addr %q; want %v %q", cfg.ContainerdBuildKitRootless, cfg.ContainerdBuildKitAddr, tc.want, tc.wantAddr)
			}
			if cfg.ContainerdBuildMaxImageBytes != DefaultBuildMaxImageBytes {
				t.Fatalf("max image bytes = %d", cfg.ContainerdBuildMaxImageBytes)
			}
		})
	}
	for _, tc := range []struct {
		name, mode, raw, max, want string
	}{
		{name: "split with root BuildKit", mode: "split", raw: "false", want: "rootless BuildKit"},
		{name: "not a boolean", raw: "yes please", want: "SB_CONTAINERD_BUILDKIT_ROOTLESS"},
		{name: "a bound of zero", max: "0", want: "SB_CONTAINERD_BUILD_MAX_IMAGE_BYTES"},
		{name: "a negative bound", max: "-1", want: "SB_CONTAINERD_BUILD_MAX_IMAGE_BYTES"},
		{name: "a bound with a unit", max: "16GiB", want: "SB_CONTAINERD_BUILD_MAX_IMAGE_BYTES"},
	} {
		t.Run("refused: "+tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			t.Setenv("SB_PRIVILEGE_MODE", tc.mode)
			t.Setenv("SB_CONTAINERD_BUILDKIT_ROOTLESS", tc.raw)
			t.Setenv("SB_CONTAINERD_BUILD_MAX_IMAGE_BYTES", tc.max)
			if _, err := Load(); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
	t.Run("the bound is settable", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "operator-pat")
		t.Setenv("SB_CONTAINERD_BUILD_MAX_IMAGE_BYTES", "1048576")
		if cfg, err := Load(); err != nil || cfg.ContainerdBuildMaxImageBytes != 1<<20 {
			t.Fatalf("bound %d, %v", cfg.ContainerdBuildMaxImageBytes, err)
		}
	})
}
