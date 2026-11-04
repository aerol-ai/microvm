package config

import (
	"strings"
	"testing"
)

// The watchdog and the daemon find each other through SB_LIVENESS_SOCKET:
// it defaults on, "off" turns it off (the watchdog then probes /health), and
// a relative path is refused rather than resolved against the daemon's
// working directory.
func TestLivenessSocketConfig(t *testing.T) {
	cases := []struct {
		name, env, want, wantErr string
	}{
		{name: "default", want: DefaultLivenessSocket},
		{name: "own path", env: " /run/x/live.sock ", want: "/run/x/live.sock"},
		{name: "off", env: "OFF", want: ""},
		{name: "cleared", env: envClearSentinel, want: ""},
		{name: "relative is refused", env: "live.sock", wantErr: "SB_LIVENESS_SOCKET must be an absolute path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_LIVENESS_SOCKET", tc.env)
			t.Setenv("SB_ENTERPRISE_MODE", "false")
			t.Setenv("SB_PAT_TOKEN", "pat-token")
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load error = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.LivenessSocket != tc.want {
				t.Fatalf("LivenessSocket = %q, want %q", cfg.LivenessSocket, tc.want)
			}
		})
	}
}
