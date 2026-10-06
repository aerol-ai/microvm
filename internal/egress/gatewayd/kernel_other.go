//go:build !linux

package gatewayd

import "github.com/aerol-ai/microvm/internal/egress"

// productionKernel off Linux is an in-memory backend: the gateway only runs
// for real on Linux; this keeps the binary buildable on developer hosts.
func productionKernel() (egress.Backend, egress.ConntrackFlusher) {
	return egress.NewMemBackend(), nil
}

func hardenProcess() error { return nil }
