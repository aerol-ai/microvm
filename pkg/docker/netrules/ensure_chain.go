package netrules

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
		// Netlink backend on docker-only hosts targets an existing DOCKER-USER;
		// containerd-only bootstrap lands with the netlink chain path in Phase 5.
		m.chainReady.Store(true)
		return nil
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

// ResetChainLatch clears the bootstrap latch. Test-only seam.
func (m *Manager) ResetChainLatch() {
	if m == nil {
		return
	}
	m.chainReady.Store(false)
}
