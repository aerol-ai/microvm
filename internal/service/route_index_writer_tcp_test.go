package service

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/aerol-ai/microvm/internal/network/hostport"
	"github.com/aerol-ai/microvm/internal/routedns"
)

type recordingTCPForwarder struct {
	rules   map[int]hostport.Target
	removed []int
}

func (f *recordingTCPForwarder) Ensure(hp int, t hostport.Target) error {
	if f.rules == nil {
		f.rules = map[int]hostport.Target{}
	}
	f.rules[hp] = t
	return nil
}

func (f *recordingTCPForwarder) Remove(hp int) error {
	delete(f.rules, hp)
	f.removed = append(f.removed, hp)
	return nil
}

// Raw TCP (review T7): each TCP intent becomes exactly one kernel forwarding
// rule, and Caddy's tcp-port-N server ids map back onto host ports.
func TestIndexRouteWriterTCPIntents(t *testing.T) {
	ctx := context.Background()
	fwd := &recordingTCPForwarder{}
	w := newIndexRouteWriter(routedns.NewOwnerTable(), "d.test")
	w.tcp, w.redirectPort = fwd, 21214
	w.lookupIP = func(host string) ([]net.IP, error) {
		switch host {
		case "owner-2.internal":
			return []net.IP{net.ParseIP("fd00::2"), net.ParseIP("10.1.0.2")}, nil
		case "v6only.internal":
			return []net.IP{net.ParseIP("fd00::3")}, nil
		}
		return nil, errors.New("nxdomain")
	}
	redirect := hostport.Target{Kind: hostport.Redirect, RedirectPort: 21214}

	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	must(w.UpsertTCPRoute(ctx, "sb", "10.0.0.5", 5432, 41000))
	if got := fwd.rules[41000]; got != (hostport.Target{Kind: hostport.DNAT, Addr: netip.MustParseAddrPort("10.0.0.5:5432")}) {
		t.Fatalf("container target = %+v, want DNAT to the container", got)
	}
	// WASM/isolate mediators listen on loopback: the kernel can't DNAT an
	// outside connection there, so the sandboxd listener takes it.
	for i, ip := range []string{"127.0.0.1", "", "fd00::9"} {
		must(w.UpsertTCPRoute(ctx, "sb", ip, 7000, 41001+i))
		if got := fwd.rules[41001+i]; got != redirect {
			t.Fatalf("target %q = %+v, want redirect", ip, got)
		}
	}
	must(w.UpsertWakeTCPRoute(ctx, "sb", 9, 41010, "10.0.0.5"))
	if got := fwd.rules[41010]; got != redirect {
		t.Fatalf("wake target = %+v, want redirect", got)
	}

	// Ingress → owner: masqueraded so the owner replies through this node.
	must(w.UpsertTCPProxyRoute(ctx, "sb", 5432, 41020, "10.1.0.9", 41020))
	must(w.UpsertTCPProxyRoute(ctx, "sb", 5432, 41021, "owner-2.internal", 41021))
	if got := fwd.rules[41021]; got != (hostport.Target{Kind: hostport.DNAT, Addr: netip.MustParseAddrPort("10.1.0.2:41021"), Masquerade: true}) {
		t.Fatalf("proxy target = %+v, want masqueraded DNAT to the owner's IPv4", got)
	}
	for _, host := range []string{"v6only.internal", "missing.internal", "fd00::4"} {
		if err := w.UpsertTCPProxyRoute(ctx, "sb", 5432, 41030, host, 41030); err == nil {
			t.Fatalf("owner %q: want an error, not a rule", host)
		}
	}
	if _, ok := fwd.rules[41030]; ok {
		t.Fatal("a rule was installed for an unresolvable owner")
	}

	must(w.DeleteTCPRoute(ctx, 41000))
	must(w.DeleteTCPServer(ctx, "tcp-port-41020"))
	must(w.DeleteTCPServer(ctx, "tls-mux"))          // not a host-port server
	must(w.DeleteTCPServer(ctx, "tcp-port-garbage")) // malformed: ignored
	if len(fwd.removed) != 2 || fwd.removed[0] != 41000 || fwd.removed[1] != 41020 {
		t.Fatalf("removed %v, want [41000 41020]", fwd.removed)
	}
}

// With no forwarder wired, every TCP intent is a no-op (the flag-off and
// single-node paths never touch iptables).
func TestIndexRouteWriterTCPNoForwarder(t *testing.T) {
	ctx := context.Background()
	w := newIndexRouteWriter(routedns.NewOwnerTable(), "d.test")
	for name, err := range map[string]error{
		"upsert": w.UpsertTCPRoute(ctx, "sb", "10.0.0.5", 1, 2),
		"wake":   w.UpsertWakeTCPRoute(ctx, "sb", 1, 2, ""),
		"proxy":  w.UpsertTCPProxyRoute(ctx, "sb", 1, 2, "nowhere.invalid", 2),
		"delete": w.DeleteTCPRoute(ctx, 2),
		"server": w.DeleteTCPServer(ctx, "tcp-port-2"),
		"sni":    w.UpsertSNIPassthroughRoute(ctx, "sb", "h", "10.0.0.5", 443),
	} {
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
}
