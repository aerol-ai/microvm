package config

import (
	"strings"
	"testing"
	"time"
)

func TestAPIAdmissionConfig(t *testing.T) {
	cases := []struct {
		name, max, wait string
		wantMax         int
		wantWait        time.Duration
		wantErr         string
	}{
		{name: "defaults", wantMax: DefaultAPIListMaxInflight, wantWait: DefaultAPIListQueueWait},
		{name: "own values", max: " 64 ", wait: "2s", wantMax: 64, wantWait: 2 * time.Second},
		{name: "no limit and no wait", max: "0", wait: "0s", wantMax: 0, wantWait: 0},
		{name: "a typo in the limit is refused", max: "sixteen", wantErr: "SB_API_LIST_MAX_INFLIGHT"},
		{name: "a negative limit is refused", max: "-1", wantErr: "SB_API_LIST_MAX_INFLIGHT"},
		{name: "a typo in the wait is refused", wait: "500", wantErr: "SB_API_LIST_QUEUE_WAIT"},
		{name: "a negative wait is refused", wait: "-1s", wantErr: "SB_API_LIST_QUEUE_WAIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_API_LIST_MAX_INFLIGHT", tc.max)
			t.Setenv("SB_API_LIST_QUEUE_WAIT", tc.wait)
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
			if cfg.APIListMaxInflight != tc.wantMax || cfg.APIListQueueWait != tc.wantWait {
				t.Fatalf("got max %d wait %v, want %d %v", cfg.APIListMaxInflight, cfg.APIListQueueWait, tc.wantMax, tc.wantWait)
			}
		})
	}
}
