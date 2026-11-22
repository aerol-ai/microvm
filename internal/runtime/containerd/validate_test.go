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
		// Names the sandboxes' cgroup parent keeps for AerolVM's own
		// processes: containerd's group and the host-process runtimes'.
		{"machinery group _runtime rejected", "_runtime", true},
		{"host runtime group aerolvm-wasm rejected", "aerolvm-wasm", true},
		{"host runtime group aerolvm-vmm rejected", "aerolvm-vmm", true},
		{"netns pool slot ok", "aerol-netns-7", false},
		{"parked slot ok", "park-1", false},
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
