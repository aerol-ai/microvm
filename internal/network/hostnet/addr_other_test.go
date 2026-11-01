//go:build !linux

package hostnet

import (
	"strings"
	"testing"
)

func TestNetnsIPv4AddrsOtherIsUnsupported(t *testing.T) {
	addrs, err := NetnsIPv4Addrs("/run/netns/x")
	if err == nil || addrs != nil || !strings.Contains(err.Error(), "Linux-only") {
		t.Fatalf("addrs=%v err=%v", addrs, err)
	}
}
