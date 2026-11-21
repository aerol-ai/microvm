package config

import (
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/privmode"
)

// SB_PRIVILEGE_MODE (plans/security-gaps-m1-m4.md D22): absent is single,
// today's mode, so an agent upgraded in place onto an old node keeps it
// (D5); a value that is neither name stops the start.
func TestLoadPrivilegeMode(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want privmode.Mode
	}{{"", privmode.Single}, {"single", privmode.Single}, {"split", privmode.Split}, {" SPLIT ", privmode.Split}} {
		t.Run("value "+tc.raw, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			t.Setenv("SB_PRIVILEGE_MODE", tc.raw)
			cfg, err := Load()
			if err != nil || cfg.PrivilegeMode != tc.want {
				t.Fatalf("PrivilegeMode = %q, %v; want %q", cfg.PrivilegeMode, err, tc.want)
			}
			if cfg.RootdSocket != DefaultRootdSocket {
				t.Fatalf("RootdSocket = %q", cfg.RootdSocket)
			}
		})
	}
	t.Run("an unknown mode", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "operator-pat")
		t.Setenv("SB_PRIVILEGE_MODE", "half")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SB_PRIVILEGE_MODE") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("the helper's socket", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "operator-pat")
		t.Setenv("SB_ROOTD_SOCKET", "/run/h/h.sock")
		if cfg, err := Load(); err != nil || cfg.RootdSocket != "/run/h/h.sock" {
			t.Fatalf("RootdSocket = %q, %v", cfg.RootdSocket, err)
		}
		t.Setenv("SB_ROOTD_SOCKET", "h.sock")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SB_ROOTD_SOCKET") {
			t.Fatalf("a relative socket: %v", err)
		}
	})
}
