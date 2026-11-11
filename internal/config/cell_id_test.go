package config

import (
	"strings"
	"testing"
)

// C12: SB_CELL_ID is read strictly, so a typo stops the boot instead of
// putting the node, and its sandbox IDs, in cell 1.
func TestCellIDConfig(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        int
		wantErr     bool
	}{
		{name: "default", want: 1},
		{name: "own cell", value: " 7 ", want: 7},
		{name: "highest", value: "255", want: 255},
		{name: "zero is refused", value: "0", wantErr: true},
		{name: "past one byte is refused", value: "256", wantErr: true},
		{name: "a typo is refused", value: "seven", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_CELL_ID", tc.value)
			t.Setenv("SB_ENTERPRISE_MODE", "false")
			t.Setenv("SB_PAT_TOKEN", "pat-token")
			cfg, err := Load()
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "SB_CELL_ID") {
					t.Fatalf("Load = %v, want an SB_CELL_ID error", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg.CellID != tc.want {
				t.Fatalf("CellID = %d, want %d", cfg.CellID, tc.want)
			}
		})
	}
}
