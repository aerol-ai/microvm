package netrules

import "fmt"

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
	m.chainReady.Store(true)
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
	return boot.EnsureForwardJump(chain)
}

// ResetChainLatch clears the bootstrap latch. Test-only seam.
func (m *Manager) ResetChainLatch() {
	if m == nil {
		return
	}
	m.chainReady.Store(false)
}
