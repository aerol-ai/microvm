package netrules

import "testing"

func TestManagerDisabledAndNilGuards(t *testing.T) {
	var nilMgr *Manager
	if nilMgr.Enabled() {
		t.Fatal("nil manager reported enabled")
	}
	if err := nilMgr.BlockAllEgress("10.0.0.2"); err != nil {
		t.Fatalf("nil BlockAllEgress err = %v", err)
	}
	if err := nilMgr.ClearBlockAllEgress("10.0.0.2"); err != nil {
		t.Fatalf("nil ClearBlockAllEgress err = %v", err)
	}
	if err := nilMgr.BlockAllIngress("10.0.0.2"); err != nil {
		t.Fatalf("nil BlockAllIngress err = %v", err)
	}
	if err := nilMgr.ClearBlockAllIngress("10.0.0.2"); err != nil {
		t.Fatalf("nil ClearBlockAllIngress err = %v", err)
	}

	disabled := &Manager{enabled: false}
	if disabled.Enabled() {
		t.Fatal("disabled manager reported enabled")
	}
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{name: "block_egress", run: func() error { return disabled.BlockAllEgress("10.0.0.2") }},
		{name: "clear_egress", run: func() error { return disabled.ClearBlockAllEgress("10.0.0.2") }},
		{name: "block_ingress", run: func() error { return disabled.BlockAllIngress("10.0.0.2") }},
		{name: "clear_ingress", run: func() error { return disabled.ClearBlockAllIngress("10.0.0.2") }},
		{name: "empty_ip_block_egress", run: func() error { return disabled.BlockAllEgress("") }},
		{name: "empty_ip_clear_egress", run: func() error { return disabled.ClearBlockAllEgress("") }},
		{name: "empty_ip_block_ingress", run: func() error { return disabled.BlockAllIngress("") }},
		{name: "empty_ip_clear_ingress", run: func() error { return disabled.ClearBlockAllIngress("") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err != nil {
				t.Fatalf("%s err = %v", tc.name, err)
			}
		})
	}
}

func TestNew_DisabledReturnsDisabledManager(t *testing.T) {
	m, err := New(false)
	if err != nil {
		t.Fatalf("New(false) err = %v", err)
	}
	if m == nil || m.Enabled() {
		t.Fatalf("New(false) = %+v, want non-nil disabled manager", m)
	}
}
