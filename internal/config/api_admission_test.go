package config

import (
	"strings"
	"testing"
	"time"
)

func TestAPIAdmissionConfig(t *testing.T) {
	cases := []struct {
		name, max, perTenant, wait string
		wantMax, wantPerTenant     int
		wantWait                   time.Duration
		wantErr                    string
	}{
		{name: "defaults", wantMax: DefaultAPIListMaxInflight, wantPerTenant: 4, wantWait: DefaultAPIListQueueWait},
		{name: "own values", max: " 64 ", wait: "2s", wantMax: 64, wantPerTenant: 16, wantWait: 2 * time.Second},
		{name: "no limit and no wait", max: "0", wait: "0s", wantMax: 0, wantPerTenant: 0, wantWait: 0},
		{name: "a small gate still gives a tenant one slot", max: "3", wantMax: 3, wantPerTenant: 1, wantWait: DefaultAPIListQueueWait},
		{name: "own share", max: "8", perTenant: " 2 ", wantMax: 8, wantPerTenant: 2, wantWait: DefaultAPIListQueueWait},
		{name: "a share of the whole gate", max: "8", perTenant: "8", wantMax: 8, wantPerTenant: 8, wantWait: DefaultAPIListQueueWait},
		{name: "0 = no per-tenant share", max: "8", perTenant: "0", wantMax: 8, wantPerTenant: 8, wantWait: DefaultAPIListQueueWait},
		{name: "a share left set while the gate is off does not refuse the boot", max: "0", perTenant: "4", wantMax: 0, wantPerTenant: 0, wantWait: DefaultAPIListQueueWait},
		{name: "a share over the gate is refused", max: "8", perTenant: "9", wantErr: "SB_API_LIST_MAX_INFLIGHT_PER_TENANT (9) is more than SB_API_LIST_MAX_INFLIGHT (8)"},
		{name: "a typo in the share is refused", perTenant: "four", wantErr: "SB_API_LIST_MAX_INFLIGHT_PER_TENANT"},
		{name: "a negative share is refused", perTenant: "-1", wantErr: "SB_API_LIST_MAX_INFLIGHT_PER_TENANT"},
		{name: "a typo in the limit is refused", max: "sixteen", wantErr: "SB_API_LIST_MAX_INFLIGHT"},
		{name: "a negative limit is refused", max: "-1", wantErr: "SB_API_LIST_MAX_INFLIGHT"},
		{name: "a typo in the wait is refused", wait: "500", wantErr: "SB_API_LIST_QUEUE_WAIT"},
		{name: "a negative wait is refused", wait: "-1s", wantErr: "SB_API_LIST_QUEUE_WAIT"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_API_LIST_MAX_INFLIGHT", tc.max)
			t.Setenv("SB_API_LIST_MAX_INFLIGHT_PER_TENANT", tc.perTenant)
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
			if cfg.APIListMaxInflight != tc.wantMax || cfg.APIListMaxInflightPerTenant != tc.wantPerTenant || cfg.APIListQueueWait != tc.wantWait {
				t.Fatalf("got max %d per tenant %d wait %v, want %d %d %v", cfg.APIListMaxInflight, cfg.APIListMaxInflightPerTenant, cfg.APIListQueueWait, tc.wantMax, tc.wantPerTenant, tc.wantWait)
			}
		})
	}
}
