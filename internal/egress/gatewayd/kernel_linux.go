//go:build linux

package gatewayd

import "github.com/aerol-ai/microvm/internal/egress"

func linuxKernel() (egress.Backend, egress.ConntrackFlusher) {
	return egress.NewNFTBackend(), egress.NetlinkConntrack{}
}

// productionKernel is the nftables backend. The coverage run is unprivileged,
// so tests point this at the in-memory backend; the kernel suite keeps this.
var productionKernel = linuxKernel

// hardenProcess keeps the gateway out of core dumps and ptrace-by-same-uid
// (PR_SET_DUMPABLE=0, CEO D22): it may hold upstream-proxy credentials.
func hardenProcess() error {
	return unixPrctlNoDump()
}
