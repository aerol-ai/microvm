package config

import (
	"strings"
	"testing"
	"time"
)

func TestReadyLeaderGraceConfig(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        time.Duration
		wantErr     bool
	}{
		{name: "default", want: DefaultReadyLeaderGrace},
		{name: "own grace", value: " 30s ", want: 30 * time.Second},
		{name: "zero is refused", value: "0s", wantErr: true},
		{name: "negative is refused", value: "-5s", wantErr: true},
		{name: "a bare number is refused", value: "10", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_READY_LEADER_GRACE", tc.value)
			t.Setenv("SB_ENTERPRISE_MODE", "false")
			t.Setenv("SB_PAT_TOKEN", "pat-token")
			cfg, err := Load()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "SB_READY_LEADER_GRACE") {
					t.Fatalf("Load = %v, want an SB_READY_LEADER_GRACE error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.ReadyLeaderGrace != tc.want {
				t.Fatalf("ReadyLeaderGrace = %v, want %v", cfg.ReadyLeaderGrace, tc.want)
			}
		})
	}
}
