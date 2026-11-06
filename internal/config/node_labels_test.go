package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestNodeLabelsConfig(t *testing.T) {
	cases := []struct {
		name    string
		zone    string
		labels  string
		want    map[string]string
		wantErr string
	}{
		{name: "unset is no labels", want: nil},
		{name: "zone only", zone: "eu-west-1a", want: map[string]string{"zone": "eu-west-1a"}},
		{name: "zone and labels", zone: "eu-west-1a", labels: "gpu=a10,tier=pci",
			want: map[string]string{"zone": "eu-west-1a", "gpu": "a10", "tier": "pci"}},
		{name: "a typo fails the boot", labels: "gpu a10", wantErr: "SB_NODE_LABELS / SB_NODE_ZONE"},
		{name: "zone disagreement fails the boot", zone: "z1", labels: "zone=z2", wantErr: "disagrees"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_ENTERPRISE_MODE", "false")
			t.Setenv("SB_PAT_TOKEN", "pat-token")
			t.Setenv("SB_NODE_ZONE", tc.zone)
			t.Setenv("SB_NODE_LABELS", tc.labels)
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
			if !reflect.DeepEqual(cfg.NodeLabels, tc.want) {
				t.Fatalf("NodeLabels = %v, want %v", cfg.NodeLabels, tc.want)
			}
		})
	}
}
