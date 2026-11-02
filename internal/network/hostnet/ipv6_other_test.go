//go:build !linux

package hostnet

import "testing"

func TestDisableIPv6InNetnsOtherWritesCurrent(t *testing.T) {
	root := fakeIPv6Conf(t)
	if err := DisableIPv6InNetns("/run/netns/x"); err != nil {
		t.Fatal(err)
	}
	if got := readDisable(t, root, "all"); got != "1" {
		t.Fatalf("all = %q", got)
	}
}
