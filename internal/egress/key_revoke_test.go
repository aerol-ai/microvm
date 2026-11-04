package egress

import (
	"context"
	"errors"
	"net"
	"testing"
)

// A key revoke (plans/customer-key-custody.md §10, eng D21): the gateway
// drops every sandbox's injection secrets and closes only the inspected
// connections.
func TestDropSecretsAndCloseInspected(t *testing.T) {
	g, _, _ := newTestGateway(t)
	spec := allowSpec("sb", ipA, "api.example.com")
	spec.Secrets = map[string]string{"TOKEN": "s3cret"}
	if err := g.Attach(spec); err != nil {
		t.Fatal(err)
	}
	inspected, ip := net.Pipe()
	defer ip.Close()
	spliced, sp := net.Pipe()
	defer sp.Close()
	g.Track("sb", "api.example.com", 443, inspected).MarkInspected()
	keep := g.Track("sb", "other.example.com", 443, spliced)
	defer keep.Close()

	g.DropSecrets()
	src, ok := g.Source(ipA)
	if !ok || src.Spec.Secrets != nil {
		t.Fatalf("secrets after drop = %v", src.Spec.Secrets)
	}
	if n := g.CloseInspected(); n != 1 {
		t.Fatalf("closed %d, want the one inspected connection", n)
	}
	if _, err := inspected.Write([]byte("x")); err == nil {
		t.Fatal("inspected connection still open")
	}
	if g.CloseInspected() != 0 {
		t.Fatal("a spliced connection was closed")
	}
}

func TestClearInspectCAOverTheWire(t *testing.T) {
	var cleared, contacts int
	c, _, _, _ := startServer(t, ServerHooks{
		ClearInspectCA: func() error { cleared++; return nil },
		Contact:        func() { contacts++ },
	}, nil)
	ctx := context.Background()
	if err := c.ClearInspectCA(ctx); err != nil || cleared != 1 {
		t.Fatalf("ClearInspectCA = %v (cleared %d)", err, cleared)
	}
	if contacts == 0 {
		t.Fatal("Contact hook not called")
	}
	// A gateway from before the op answers "unknown op": sandboxd restarts it.
	err := c.call(ctx, "clear_something_new", nil, nil)
	if !IsUnknownOp(err) || IsUnknownOp(nil) || IsUnknownOp(ErrUnavailable) {
		t.Fatalf("IsUnknownOp(%v)", err)
	}
	if err := (Noop{}).ClearInspectCA(ctx); err != nil {
		t.Fatal(err)
	}
	bare, _, _, _ := startServer(t, ServerHooks{}, nil)
	if err := bare.ClearInspectCA(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("no hook = %v", err)
	}
}
