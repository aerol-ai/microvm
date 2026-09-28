package worker

import (
	"context"
	"testing"
)

func TestCoverage95ServerNetworkHookEdges(t *testing.T) {
	s := &Server{}
	s.bindNetworkHook("sb")
	s.clearNetworkHook()
	s.eng = &mockEngine{}
	s.bindNetworkHook("sb")
	s.clearNetworkHook()
}

func TestCoverage95NetMediatorDialError(t *testing.T) {
	m := newNetMediator()
	_, err := m.DialContext(context.Background(), "sb", "tcp", "127.0.0.1:1")
	if err == nil {
		t.Fatal("expected dial error on closed port")
	}
}
