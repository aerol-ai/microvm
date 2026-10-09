package gatewayd

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/aerol-ai/microvm/internal/egress"
)

// TestBridgeListenersTapPool (Phase 4): the Firecracker TAP pool moves the
// gateway to one wildcard listener set that serves every bridge; dropping
// it rebinds the per-bridge addresses on the same ports.
func TestBridgeListenersTapPool(t *testing.T) {
	var binds []string
	failAddr := ""
	listen := func(network, addr string) (net.Listener, net.PacketConn, error) {
		binds = append(binds, network+" "+addr)
		if addr == failAddr {
			return nil, nil, errors.New("address in use")
		}
		return listenFreebind(network, addr)
	}
	dnsPort, proxyPort := freePort(t), freePort(t)
	b := newBridgeListeners(dnsPort, proxyPort, dns.HandlerFunc(func(dns.ResponseWriter, *dns.Msg) {}), func(ln net.Listener) {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}, listen, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer b.Close()

	loBridge := egress.Bridge{Name: "lo", GatewayIP: lo}
	pool := egress.TapPoolBridge(netip.MustParsePrefix("172.16.9.5/24"))
	if !pool.Wildcard() || loBridge.Wildcard() || pool.Subnet != netip.MustParsePrefix("172.16.9.0/24") {
		t.Fatalf("pool bridge = %+v", pool)
	}
	if err := b.Set([]egress.Bridge{loBridge}); err != nil {
		t.Fatal(err)
	}
	addrs := strings.Join(b.Addrs(), " ")
	if !strings.Contains(addrs, "127.0.0.1:") || strings.Contains(addrs, "0.0.0.0:") {
		t.Fatalf("per-bridge listeners: %s", addrs)
	}

	// The pool arrives: the 127.0.0.1 set closes first, so the wildcard can
	// take the same ports, and serves the bridge too.
	if err := b.Set([]egress.Bridge{loBridge, pool}); err != nil {
		t.Fatal(err)
	}
	addrs = strings.Join(b.Addrs(), " ")
	if !strings.Contains(addrs, "0.0.0.0:") || strings.Contains(addrs, "127.0.0.1:") || len(b.Addrs()) != 3 {
		t.Fatalf("wildcard listeners: %s", addrs)
	}
	c, err := net.Dial("tcp", net.JoinHostPort(lo.String(), strconv.Itoa(int(proxyPort))))
	if err != nil {
		t.Fatalf("the wildcard must serve the bridge address: %v", err)
	}
	_ = c.Close()
	if got := b.Bridges(); len(got) != 2 {
		t.Fatalf("bridges = %v", got)
	}

	// Gone again: back to the bridge's own address.
	if err := b.Set([]egress.Bridge{loBridge}); err != nil {
		t.Fatal(err)
	}
	if addrs = strings.Join(b.Addrs(), " "); !strings.Contains(addrs, "127.0.0.1:") || strings.Contains(addrs, "0.0.0.0:") {
		t.Fatalf("back to per-bridge: %s", addrs)
	}

	// A failed bind is reported and leaves nothing half-bound.
	b.Close()
	failAddr = net.JoinHostPort("0.0.0.0", strconv.Itoa(int(proxyPort)))
	if err := b.Set([]egress.Bridge{pool}); err == nil || !strings.Contains(err.Error(), "bridge *") {
		t.Fatalf("bind failure: %v", err)
	}
	if len(b.Addrs()) != 0 {
		t.Fatalf("half-bound: %v", b.Addrs())
	}
	if len(binds) == 0 {
		t.Fatal("no binds recorded")
	}
}
