package auditlog

import (
	"context"
	"testing"
)

// TestSSHGatewayCallWireForm: the value a bridged SSH call travels with
// between nodes round-trips exactly, whatever the session name holds, and
// anything that is not one sandbox plus at most one open marker is refused.
func TestSSHGatewayCallWireForm(t *testing.T) {
	roundTrips := []SSHGatewayCall{
		{SandboxID: "sb-1"},
		{SandboxID: "sb-1", Open: true, Session: "default"},
		{SandboxID: "sb-1", Open: true},
		{SandboxID: "sb-1", Open: true, Session: "a b&open=x\r\nX-Evil: 1"},
	}
	for _, want := range roundTrips {
		raw := want.Encode()
		got, ok := ParseSSHGatewayCall(raw)
		if !ok || got != want {
			t.Fatalf("%q parsed to %+v ok=%v, want %+v", raw, got, ok, want)
		}
	}
	if got := (SSHGatewayCall{SandboxID: "sb-1", Session: "ignored"}).Encode(); got != "sandbox=sb-1" {
		t.Fatalf("a session without open encoded to %q: only the opening call names it", got)
	}

	refused := []struct{ name, raw string }{
		{"empty", ""},
		{"blank", "   "},
		{"no sandbox", "open=default"},
		{"blank sandbox", "sandbox=%20"},
		{"sandbox named twice", "sandbox=sb-1&sandbox=sb-2"},
		{"open sent twice", "sandbox=sb-1&open=a&open=b"},
		{"not a query", "sandbox=%zz"},
	}
	for _, tc := range refused {
		t.Run(tc.name, func(t *testing.T) {
			if got, ok := ParseSSHGatewayCall(tc.raw); ok {
				t.Fatalf("%q parsed to %+v, want refused", tc.raw, got)
			}
		})
	}
}

func TestSSHGatewayCallContext(t *testing.T) {
	if _, ok := SSHGatewayCallFromContext(context.Background()); ok {
		t.Fatal("an empty context carries a bridged call")
	}
	var nilCtx context.Context
	if _, ok := SSHGatewayCallFromContext(nilCtx); ok {
		t.Fatal("a nil context carries a bridged call")
	}
	want := SSHGatewayCall{SandboxID: "sb-1", Open: true, Session: "default"}
	got, ok := SSHGatewayCallFromContext(ContextWithSSHGatewayCall(nilCtx, want))
	if !ok || got != want {
		t.Fatalf("context carried %+v ok=%v, want %+v", got, ok, want)
	}
}
