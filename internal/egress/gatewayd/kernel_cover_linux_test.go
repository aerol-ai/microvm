package gatewayd

import (
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/egress"
)

// TestLinuxKernelIsNFT: production runs the nftables backend and netlink
// conntrack; building them touches no kernel state, so this needs no
// privileges.
func TestLinuxKernelIsNFT(t *testing.T) {
	be, ct := linuxKernel()
	if _, ok := be.(*egress.NFTBackend); !ok {
		t.Fatalf("backend = %T", be)
	}
	if _, ok := ct.(egress.NetlinkConntrack); !ok {
		t.Fatalf("conntrack = %T", ct)
	}
}

type refusedRawConn struct{}

var errRawConn = errors.New("raw conn closed")

func (refusedRawConn) Control(func(uintptr)) error    { return errRawConn }
func (refusedRawConn) Read(func(uintptr) bool) error  { return errRawConn }
func (refusedRawConn) Write(func(uintptr) bool) error { return errRawConn }

// TestFreebindControlFails: a socket that can't take IP_FREEBIND fails the
// listen rather than binding without it.
func TestFreebindControlFails(t *testing.T) {
	if err := freebindControl("tcp4", "127.0.0.1:0", refusedRawConn{}); !errors.Is(err, errRawConn) {
		t.Fatalf("freebindControl = %v", err)
	}
}
