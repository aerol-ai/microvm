package hostnet

import "testing"

func TestNetnsIPv4AddrsNeedsAPath(t *testing.T) {
	for _, p := range []string{"", "  "} {
		if _, err := NetnsIPv4Addrs(p); err == nil {
			t.Fatalf("NetnsIPv4Addrs(%q) must fail", p)
		}
	}
}
