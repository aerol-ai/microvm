package egress

import (
	"fmt"
	"sync"
)

// MemBackend is an in-memory Backend for tests in this and other packages.
// It models the properties the gateway relies on: per-call atomicity,
// layout presence, and idempotent element add/delete.
type MemBackend struct {
	mu      sync.Mutex
	present bool
	layout  LayoutConfig
	sets    map[string]map[Elem]struct{}
	// FailApply, when set, makes the next Apply/Replace fail without
	// changing anything (all-or-nothing, like an nft transaction).
	FailApply error
	// Calls counts Apply+Replace transactions.
	Calls int
}

// NewMemBackend returns an empty MemBackend with no layout.
func NewMemBackend() *MemBackend { return &MemBackend{sets: map[string]map[Elem]struct{}{}} }

func (m *MemBackend) EnsureLayout(cfg LayoutConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.present && m.layout == cfg {
		return nil
	}
	m.present, m.layout = true, cfg
	m.sets = map[string]map[Elem]struct{}{}
	return nil
}

func (m *MemBackend) CheckLayout() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.present {
		return ErrLayoutMissing
	}
	return nil
}

// DropLayout simulates `nft flush ruleset` / table deletion.
func (m *MemBackend) DropLayout() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.present = false
	m.sets = map[string]map[Elem]struct{}{}
}

func key(e Elem) Elem { e.Timeout = 0; return e }

func (m *MemBackend) Apply(ops []Op) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failLocked(); err != nil {
		return err
	}
	m.Calls++
	for _, op := range ops {
		set := m.setLocked(op.Set)
		for _, e := range op.Elems {
			if op.Del {
				delete(set, key(e))
			} else {
				set[key(e)] = struct{}{}
			}
		}
	}
	return nil
}

func (m *MemBackend) Replace(contents map[string][]Elem) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.failLocked(); err != nil {
		return err
	}
	m.Calls++
	for name, elems := range contents {
		set := map[Elem]struct{}{}
		for _, e := range elems {
			set[key(e)] = struct{}{}
		}
		m.sets[name] = set
	}
	return nil
}

func (m *MemBackend) List(name string) ([]Elem, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.present {
		return nil, ErrLayoutMissing
	}
	out := make([]Elem, 0, len(m.sets[name]))
	for e := range m.sets[name] {
		out = append(out, e)
	}
	return out, nil
}

// Has reports whether a set holds an element (ignoring timeouts).
func (m *MemBackend) Has(name string, e Elem) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.sets[name][key(e)]
	return ok
}

// Len returns a set's element count.
func (m *MemBackend) Len(name string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sets[name])
}

func (m *MemBackend) setLocked(name string) map[Elem]struct{} {
	s := m.sets[name]
	if s == nil {
		s = map[Elem]struct{}{}
		m.sets[name] = s
	}
	return s
}

func (m *MemBackend) failLocked() error {
	if !m.present {
		return fmt.Errorf("apply: %w", ErrLayoutMissing)
	}
	if m.FailApply != nil {
		return m.FailApply
	}
	return nil
}
