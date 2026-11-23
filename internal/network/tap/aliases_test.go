package tap

import (
	"strings"
	"testing"
)

// TestAliases: tap's names are taphost's, so a caller of tap keeps the
// code it had (the TAP code moved for the root helper, M1 PR 9b).
func TestAliases(t *testing.T) {
	if h := NewHost("/usr/sbin/ip"); h == nil || h.IPCmd != "/usr/sbin/ip" {
		t.Fatalf("NewHost = %+v", h)
	}
	if err := EnsureNAT(nil, "not-a-cidr"); err == nil || !strings.Contains(err.Error(), "tap nat") {
		t.Fatalf("EnsureNAT: %v", err)
	}
	if err := EnsureIsolation(nil, "not-a-cidr"); err == nil || !strings.Contains(err.Error(), "tap isolation") {
		t.Fatalf("EnsureIsolation: %v", err)
	}
	if IsolationChain != "AEROLVM-FC-ISOLATE" {
		t.Fatalf("IsolationChain %q", IsolationChain)
	}
}
