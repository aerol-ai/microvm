package containerd

import (
	"strings"
	"testing"
)

func TestValidateSandboxID(t *testing.T) {
	cases := []struct {
		name    string
		id      string
		wantErr bool
	}{
		{"ok alnum dash underscore", "sb-abc_123", false},
		{"empty rejected", "", true},
		{"path traversal rejected", "../../etc/passwd", true},
		{"slash rejected", "sb/evil", true},
		{"dot rejected", "sb.evil", true},
		{"too long rejected", strings.Repeat("a", 129), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSandboxID(tc.id)
			if (err != nil) != tc.wantErr {
				t.Fatalf("validateSandboxID(%q) err = %v, wantErr %v", tc.id, err, tc.wantErr)
			}
		})
	}
}
