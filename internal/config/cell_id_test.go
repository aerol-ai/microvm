package config

import (
	"maps"
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

// C16: the federation's key and the other cells' addresses are read
// strictly too: a wrong one routes sandboxes to the wrong cell.
func TestCellRoutingConfig(t *testing.T) {
	key := "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=" // 32 bytes of 7
	for _, tc := range []struct {
		name, key, endpoints string
		want                 map[int]string
		wantKey              bool
		wantErr              string
	}{
		{name: "neither"},
		{name: "a key alone", key: key, wantKey: true},
		{name: "a short key", key: "c2hvcnQ=", wantErr: "SB_CELL_ID_KEY"},
		{name: "not base64", key: "%%%", wantErr: "SB_CELL_ID_KEY"},
		{name: "addresses without a key", endpoints: "2=https://cell2.example.com", wantErr: "SB_CELL_ENDPOINTS needs SB_CELL_ID_KEY"},
		{
			name: "addresses", key: key, wantKey: true,
			endpoints: " 2=https://cell2.example.com/ , 1=https://self.example.com,3=http://10.0.0.3:8080",
			want:      map[int]string{2: "https://cell2.example.com", 3: "http://10.0.0.3:8080"},
		},
		{name: "no address", key: key, endpoints: "2", wantErr: "SB_CELL_ENDPOINTS"},
		{name: "cell zero", key: key, endpoints: "0=https://a.example.com", wantErr: "SB_CELL_ENDPOINTS"},
		{name: "past one byte", key: key, endpoints: "256=https://a.example.com", wantErr: "SB_CELL_ENDPOINTS"},
		{name: "not http", key: key, endpoints: "2=ftp://a.example.com", wantErr: "SB_CELL_ENDPOINTS"},
		{name: "no host", key: key, endpoints: "2=https://", wantErr: "SB_CELL_ENDPOINTS"},
		{name: "not a number", key: key, endpoints: "two=https://a.example.com", wantErr: "SB_CELL_ENDPOINTS"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_CELL_ID_KEY", tc.key)
			t.Setenv("SB_CELL_ENDPOINTS", tc.endpoints)
			t.Setenv("SB_ENTERPRISE_MODE", "false")
			t.Setenv("SB_PAT_TOKEN", "pat-token")
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load = %v, want an error naming %s", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if (len(cfg.CellIDKey) == 32) != tc.wantKey {
				t.Fatalf("CellIDKey has %d bytes, want a key: %v", len(cfg.CellIDKey), tc.wantKey)
			}
			if !maps.Equal(cfg.CellEndpoints, tc.want) {
				t.Fatalf("CellEndpoints = %v, want %v", cfg.CellEndpoints, tc.want)
			}
		})
	}
}
