//go:build linux

package gatewayd

import "github.com/aerol-ai/microvm/internal/egress"

func productionKernel() (egress.Backend, egress.ConntrackFlusher) {
	return egress.NewNFTBackend(), egress.NetlinkConntrack{}
}

// hardenProcess keeps the gateway out of core dumps and ptrace-by-same-uid
// (PR_SET_DUMPABLE=0, CEO D22): it may hold upstream-proxy credentials.
func hardenProcess() error {
	return unixPrctlNoDump()
}
