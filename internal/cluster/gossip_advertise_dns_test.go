package cluster

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// A server pod advertises its headless-Service DNS name (C4). memberlist
// needs an IP, so gossip resolves the name at start; before, setupGossip
// handed memberlist the name and the server never came up.
func TestGossipAdvertiseIP(t *testing.T) {
	real, wait := lookupGossipIP, gossipResolveWait
	t.Cleanup(func() { lookupGossipIP, gossipResolveWait = real, wait })
	gossipResolveWait = 0 // one try each: the retry has its own test
	cases := []struct {
		name, host string
		ips        []net.IP
		lookupErr  error
		want       string
		wantErr    string
		wantLookup bool
	}{
		{name: "an IP is used as is", host: "10.0.0.7", want: "10.0.0.7"},
		{name: "empty stays empty", host: "", want: ""},
		{name: "a name: its IPv4 first", host: "s0.servers.ns.svc", ips: []net.IP{net.ParseIP("fd00::7"), net.ParseIP("10.0.0.7")},
			want: "10.0.0.7", wantLookup: true},
		{name: "a name with only IPv6", host: "s0.servers.ns.svc", ips: []net.IP{net.ParseIP("fd00::7")}, want: "fd00::7", wantLookup: true},
		{name: "a name that does not resolve", host: "s0.servers.ns.svc", lookupErr: errors.New("no such host"),
			wantErr: "no such host", wantLookup: true},
		{name: "a name with no address", host: "s0.servers.ns.svc", wantErr: "no address", wantLookup: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			looked := false
			lookupGossipIP = func(_ context.Context, host string) ([]net.IP, error) {
				looked = true
				if host != tc.host {
					t.Fatalf("looked up %q, want %q", host, tc.host)
				}
				return tc.ips, tc.lookupErr
			}
			got, err := gossipAdvertiseIP(tc.host)
			if looked != tc.wantLookup {
				t.Fatalf("lookup called = %v, want %v", looked, tc.wantLookup)
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

// A new pod's DNS record lags its IP by a few seconds: the start retries
// the lookup instead of exiting (the kind run's server-2 restarted on the
// first miss), and still gives up in the end.
func TestGossipAdvertiseIPRetries(t *testing.T) {
	real, wait, every := lookupGossipIP, gossipResolveWait, gossipResolveEvery
	t.Cleanup(func() { lookupGossipIP, gossipResolveWait, gossipResolveEvery = real, wait, every })
	gossipResolveWait, gossipResolveEvery = 5*time.Second, time.Millisecond
	calls := 0
	lookupGossipIP = func(context.Context, string) ([]net.IP, error) {
		calls++
		if calls < 3 {
			return nil, errors.New("no such host")
		}
		return []net.IP{net.ParseIP("10.0.0.7")}, nil
	}
	if got, err := gossipAdvertiseIP("s0.servers.ns.svc"); err != nil || got != "10.0.0.7" || calls != 3 {
		t.Fatalf("got %q, %v after %d lookups; want 10.0.0.7 after 3", got, err, calls)
	}
	gossipResolveWait = 20 * time.Millisecond
	calls = 0
	lookupGossipIP = func(context.Context, string) ([]net.IP, error) { calls++; return nil, errors.New("no such host") }
	if _, err := gossipAdvertiseIP("s0.servers.ns.svc"); err == nil || calls < 2 {
		t.Fatalf("never resolves: err = %v after %d lookups", err, calls)
	}
}

// Through setupGossip: "localhost" (the real resolver, which answers it
// from /etc/hosts without the network) stands in for a server's name.
func TestSetupGossipAdvertisesResolvedName(t *testing.T) {
	port := freeGossipPort(t)
	gn, err := setupGossip(gossipSetupConfig{
		NodeID: "s0", BindAddr: fmt.Sprintf("127.0.0.1:%d", port), AdvertiseAddr: fmt.Sprintf("localhost:%d", port),
		APIURL: "http://127.0.0.1:1", DataPlaneHost: "127.0.0.1", RaftAddr: "s0.servers.ns.svc:7000",
		InternalURL: "https://127.0.0.1:2", Role: "server",
	}, nil, nil)
	if err != nil {
		t.Fatalf("setupGossip with a DNS advertise name: %v", err)
	}
	t.Cleanup(func() { _ = gn.Close() })
	self := gn.ml.LocalNode()
	if self.Addr.String() != "127.0.0.1" && self.Addr.String() != "::1" {
		t.Fatalf("advertised %s, want localhost's IP", self.Addr)
	}
	real, wait := lookupGossipIP, gossipResolveWait
	t.Cleanup(func() { lookupGossipIP, gossipResolveWait = real, wait })
	gossipResolveWait = 0
	// No real lookup of a name that cannot resolve: offline, it can hang
	// on a resolver that is not there.
	lookupGossipIP = func(context.Context, string) ([]net.IP, error) { return nil, errors.New("no such host") }
	if _, err := setupGossip(gossipSetupConfig{NodeID: "s1", BindAddr: "127.0.0.1:0", AdvertiseAddr: "no-such-host.invalid:7001"}, nil, nil); err == nil ||
		!strings.Contains(err.Error(), "no-such-host.invalid") {
		t.Fatalf("an unresolvable name: err = %v", err)
	}
}
