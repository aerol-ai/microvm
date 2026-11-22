package workerfence

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"testing"
)

func TestNodeSpec(t *testing.T) {
	up, _ := url.Parse("https://10.9.9.9")
	spec := NodeSpec(NodeInputs{UID: 61000, AuditPort: 7000, ResolvConf: []byte("nameserver 10.0.0.2\n"), Upstream: up,
		Floor: []netip.Prefix{netip.MustParsePrefix("169.254.169.254/32")}, NodePorts: []uint16{80},
		Local: []netip.Prefix{netip.MustParsePrefix("10.0.0.5/24")}})
	var why []string
	for _, a := range spec.Allow {
		why = append(why, a.Why+" "+a.Proto+" "+a.Prefix.String())
	}
	want := []string{"audit ingest tcp 127.0.0.1/32", "name server udp 10.0.0.2/32", "name server tcp 10.0.0.2/32", "upstream proxy tcp 10.9.9.9/32"}
	if !slices.Equal(why, want) || spec.UID != 61000 || len(spec.Floor) != 1 || !slices.Equal(spec.NodePorts, []uint16{80}) || len(spec.Local) != 1 {
		t.Fatalf("spec %+v (%v)", spec, why)
	}
	for _, a := range spec.Allow {
		if a.Why == "upstream proxy" && a.PortLo != 443 {
			t.Fatalf("https proxy port %d", a.PortLo)
		}
	}
	// No audit port, no resolver, no proxy: none of their exceptions.
	if s := NodeSpec(NodeInputs{UID: 1}); len(s.Allow) != 0 {
		t.Fatalf("allows %v", s.Allow)
	}
	plain, _ := url.Parse("http://10.9.9.9:3128")
	if a := UpstreamAllows(plain); len(a) != 1 || a[0].PortLo != 3128 {
		t.Fatalf("http proxy %v", a)
	}
	bare, _ := url.Parse("http://10.9.9.9")
	if a := UpstreamAllows(bare); len(a) != 1 || a[0].PortLo != 80 {
		t.Fatalf("bare proxy %v", a)
	}
}

func TestLocalAddrs(t *testing.T) {
	got := LocalAddrs(func() ([]net.Addr, error) {
		return []net.Addr{
			&net.IPNet{IP: net.ParseIP("10.0.0.5"), Mask: net.CIDRMask(24, 32)},
			&net.IPNet{IP: net.ParseIP("10.0.0.6").To16(), Mask: net.CIDRMask(120, 128)},
			&net.IPAddr{IP: net.ParseIP("10.0.0.7")},
		}, nil
	})
	if len(got) != 2 || got[0] != netip.MustParsePrefix("10.0.0.5/24") || got[1] != netip.MustParsePrefix("10.0.0.6/24") {
		t.Fatalf("local %v", got)
	}
	if LocalAddrs(func() ([]net.Addr, error) { return nil, errors.New("no") }) != nil {
		t.Fatal("addresses from a failed read")
	}
}
