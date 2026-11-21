//go:build !linux

package rootd

import (
	"context"
	"errors"
	"net/netip"

	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// The probe network and procfs are Linux's; elsewhere every call fails.
type noEgress struct{}

func newEgressHost() EgressHost { return noEgress{} }

var errEgressNeedsLinux = errors.New("the egress gateway's host side needs Linux")

func (noEgress) ProbeSetup(context.Context, int, string, netip.Addr, netip.Prefix) (bool, error, error) {
	return false, nil, errEgressNeedsLinux
}
func (noEgress) ProbeSend(context.Context, int) error { return errEgressNeedsLinux }
func (noEgress) ProbeClose(int) error                 { return nil }
func (noEgress) ProcCgroup(int) (string, error)       { return "", errEgressNeedsLinux }
func (noEgress) Match(rootpolicy.ProcessMatch) ([]string, bool, error) {
	return nil, false, errEgressNeedsLinux
}
