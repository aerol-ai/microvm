package netrules

import (
	"fmt"
	"strings"
)

// EnsureChain bootstraps the filter user chain and its FORWARD jump once per
// Manager lifetime. Idempotent and latched like EnsureLayer4Ready: concurrent
// callers single-flight through chainMu; success sets chainReady.
func (m *Manager) EnsureChain() error {
	if !m.Enabled() {
		return nil
	}
	if m.chainReady.Load() {
		return nil
	}
	m.chainMu.Lock()
	defer m.chainMu.Unlock()
	if m.chainReady.Load() {
		return nil
	}
	boot, ok := m.ipt.(bootstrapBackend)
	if !ok {
		// Fail loud, never silently latch success. A backend that cannot create
		// the user chain + FORWARD jump means every per-IP egress rule the driver
		// later inserts is either rejected (missing chain) or never traversed
		// (missing jump) — i.e. requested isolation silently fails. Both shipped
		// backends (exec, netlink) implement bootstrapBackend; this guards against
		// a future backend regressing the contract.
		return fmt.Errorf("netrules: backend %T cannot bootstrap the %s chain; containerd egress isolation would be silently ineffective", m.ipt, m.filterChain())
	}
	chain := m.filterChain()
	if err := boot.EnsureUserChain(chain); err != nil {
		return err
	}
	if err := boot.EnsureForwardJump(chain); err != nil {
		return err
	}
	if err := m.ensureBridgeForwardAccept(); err != nil {
		return err
	}
	m.chainReady.Store(true)
	return nil
}

// ensureBridgeForwardAccept installs subnet-scoped FORWARD ACCEPT rules for the
// sandbox bridge so its traffic survives dockerd's FORWARD DROP policy. They go
// in the user chain BELOW any per-IP DROP (which Insert at position 1), so a
// blocked/egress-policied sandbox is still dropped while an unrestricted
// sandbox gets egress + sandbox↔sandbox connectivity. Idempotent; no-op when no
// bridge subnet is set (dockerd path). Uses only -s/-d matches so it is
// expressible on both the exec and netlink backends.
func (m *Manager) ensureBridgeForwardAccept() error {
	if m == nil || strings.TrimSpace(m.bridgeSubnet) == "" {
		return nil
	}
	chain := m.filterChain()
	for _, spec := range [][]string{
		{"-s", m.bridgeSubnet, "-j", "ACCEPT"},
		{"-d", m.bridgeSubnet, "-j", "ACCEPT"},
	} {
		exists, err := m.ipt.Exists("filter", chain, spec...)
		if err != nil {
			return fmt.Errorf("check bridge forward accept: %w", err)
		}
		if exists {
			continue
		}
		if err := m.ipt.Insert("filter", chain, 1, spec...); err != nil {
			return fmt.Errorf("insert bridge forward accept: %w", err)
		}
	}
	return nil
}

// ReassertChain re-runs the chain + FORWARD-jump bootstrap WITHOUT the latch, so
// a caller (e.g. the containerd netns reconcile ticker) can re-assert the jump
// after a dockerd restart flushes/reorders FORWARD and drops it. Both steps are
// idempotent; a no-op when disabled or the backend cannot bootstrap.
func (m *Manager) ReassertChain() error {
	if m == nil || !m.Enabled() {
		return nil
	}
	boot, ok := m.ipt.(bootstrapBackend)
	if !ok {
		return nil
	}
	chain := m.filterChain()
	if err := boot.EnsureUserChain(chain); err != nil {
		return err
	}
	if err := boot.EnsureForwardJump(chain); err != nil {
		return err
	}
	return m.ensureBridgeForwardAccept()
}

// ResetChainLatch clears the bootstrap latch. Test-only seam.
func (m *Manager) ResetChainLatch() {
	if m == nil {
		return
	}
	m.chainReady.Store(false)
}
