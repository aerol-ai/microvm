//go:build !linux

package netrules

import (
	"testing"
)

func TestNewEnabledManagerOffLinux(t *testing.T) {
	mgr, err := newEnabledManager("iptables", ChainAerolvmUser)
	if err != nil || mgr == nil || mgr.enabled {
		t.Fatalf("stub manager = %+v err=%v", mgr, err)
	}
}
