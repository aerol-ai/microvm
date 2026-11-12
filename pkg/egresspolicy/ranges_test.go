package egresspolicy

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// withRanges installs the node's extra lists for one test and puts the
// previous ones back: the lists are process-wide, like the node guard's.
func withRanges(t *testing.T, floor, private string) {
	t.Helper()
	prevFloor, prevPrivate := ExtraDenyFloor(), ExtraPrivateRanges()
	t.Cleanup(func() { SetRanges(prevFloor, prevPrivate) })
	f, err := ParseRanges(DenyFloorEnv, floor)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParseRanges(PrivateRangesEnv, private)
	if err != nil {
		t.Fatal(err)
	}
	SetRanges(f, p)
}

func TestParseRanges(t *testing.T) {
	tests := []struct {
		name, raw string
		want      string // FormatRanges of the result
		err       string // "" = valid
	}{
		{name: "empty", raw: "", want: ""},
		{name: "only commas and spaces", raw: " , ,", want: ""},
		{name: "a CIDR", raw: "10.96.0.0/12", want: "10.96.0.0/12"},
		{name: "a bare address is one host", raw: "10.96.0.1", want: "10.96.0.1/32"},
		{name: "a bare IPv6 address", raw: "fd00::1", want: "fd00::1/128"},
		{name: "an IPv6 range", raw: "fd00:10::/64", want: "fd00:10::/64"},
		{name: "spaces and duplicates", raw: " 10.96.0.1 , 10.96.0.1/32,172.18.0.2", want: "10.96.0.1/32,172.18.0.2/32"},
		{name: "a v4-mapped bare address", raw: "::ffff:10.96.0.1", want: "10.96.0.1/32"},
		{name: "not an address", raw: "kubernetes.default", err: "want a CIDR"},
		{name: "a bad prefix length", raw: "10.0.0.0/33", err: "want a CIDR"},
		{name: "an address with a zone", raw: "fe80::1%eth0", err: "want a CIDR"},
		{name: "host bits set", raw: "10.96.0.5/12", err: "did you mean 10.96.0.0/12"},
		{name: "every IPv4 address", raw: "0.0.0.0/0", err: "covers every address"},
		{name: "every IPv6 address", raw: "::/0", err: "covers every address"},
		{name: "a v4-mapped range", raw: "::ffff:10.0.0.0/104", err: "write an IPv4 range as IPv4"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseRanges("SB_TEST", tc.raw)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) || !strings.Contains(err.Error(), "SB_TEST") {
					t.Fatalf("err = %v, want one naming SB_TEST and %q", err, tc.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if s := FormatRanges(got); s != tc.want {
				t.Fatalf("got %q, want %q", s, tc.want)
			}
		})
	}
}

// TestLoadRangesFromEnv: a process sandboxd starts takes both lists from
// its environment, and refuses to go on with a list it cannot read.
func TestLoadRangesFromEnv(t *testing.T) {
	withRanges(t, "", "")
	t.Setenv(DenyFloorEnv, "10.96.0.1, 172.18.0.2")
	t.Setenv(PrivateRangesEnv, "198.18.0.0/15")
	if err := LoadRangesFromEnv(); err != nil {
		t.Fatal(err)
	}
	if got := FormatRanges(ExtraDenyFloor()); got != "10.96.0.1/32,172.18.0.2/32" {
		t.Fatalf("floor = %q", got)
	}
	if got := FormatRanges(ExtraPrivateRanges()); got != "198.18.0.0/15" {
		t.Fatalf("private = %q", got)
	}
	for _, env := range []string{DenyFloorEnv, PrivateRangesEnv} {
		t.Run(env, func(t *testing.T) {
			t.Setenv(env, "nope")
			if err := LoadRangesFromEnv(); err == nil || !strings.Contains(err.Error(), env) {
				t.Fatalf("err = %v, want one naming %s", err, env)
			}
			// The lists in force are kept, never half replaced.
			if len(ExtraDenyFloor()) != 2 || len(ExtraPrivateRanges()) != 1 {
				t.Fatalf("a bad value changed the lists: %v %v", ExtraDenyFloor(), ExtraPrivateRanges())
			}
		})
	}
}

// TestExtraRangesNotSetYet: a process that never set the lists has none.
func TestExtraRangesNotSetYet(t *testing.T) {
	prevFloor, prevPrivate := extraFloor.Load(), extraPrivate.Load()
	t.Cleanup(func() { extraFloor.Store(prevFloor); extraPrivate.Store(prevPrivate) })
	extraFloor.Store(nil)
	extraPrivate.Store(nil)
	if ExtraDenyFloor() != nil || ExtraPrivateRanges() != nil {
		t.Fatal("lists before SetRanges")
	}
	if err := (DialGuard{}).CheckFloor(ap("10.96.0.1:443")); err != nil {
		t.Fatalf("floor before SetRanges: %v", err)
	}
	if isPrivate(netip.MustParseAddr("198.18.0.1")) {
		t.Fatal("an extra private range before SetRanges")
	}
}

// TestExtraDenyFloor (C24): the node's extra floor is refused for every
// sandbox in every guard, and nothing opens it: not a CIDR allow, not an
// allowed name, not the internal zone, not a guard built without the
// operator file.
func TestExtraDenyFloor(t *testing.T) {
	withRanges(t, "10.96.0.1, 172.18.0.2/32, 203.0.113.7", "")
	zone := mustZone(t, []string{"cluster.local"}, []string{"10.0.0.0/8", "172.16.0.0/12"})
	openAll := mustCompile(t, Spec{AllowOut: []string{"10.0.0.0/8", "172.16.0.0/12", "203.0.113.0/24", "kubernetes.default.svc.cluster.local"}})
	learn := mustCompile(t, Spec{Mode: ModeLearn})
	tests := []struct {
		name   string
		guard  DialGuard
		policy *Policy
		target DialTarget
		rule   string // "" = allowed
	}{
		{"no policy", DialGuard{}, nil, DialTarget{Addr: ap("10.96.0.1:443")}, "10.96.0.1/32"},
		{"a CIDR allow covers it", DialGuard{}, openAll, DialTarget{Addr: ap("10.96.0.1:443")}, "10.96.0.1/32"},
		{"its name is allowed", DialGuard{}, openAll, DialTarget{Name: "kubernetes.default.svc.cluster.local", NameAllowed: true, Addr: ap("10.96.0.1:443")}, "10.96.0.1/32"},
		{"the internal zone covers it", DialGuard{Zone: zone}, nil, DialTarget{Name: "kubernetes.default.svc.cluster.local", Addr: ap("10.96.0.1:443")}, "10.96.0.1/32"},
		{"learn mode", DialGuard{}, learn, DialTarget{Addr: ap("172.18.0.2:6443")}, "172.18.0.2/32"},
		{"strict guard (isolate)", DialGuard{Strict: true}, nil, DialTarget{Addr: ap("172.18.0.2:6443")}, "172.18.0.2/32"},
		{"strict zone opt-in", DialGuard{Strict: true, Zone: zone, ZoneInStrict: true}, nil, DialTarget{Name: "api.cluster.local", Addr: ap("172.18.0.2:6443")}, "172.18.0.2/32"},
		{"a public address on the floor", DialGuard{}, openAll, DialTarget{Addr: ap("203.0.113.7:443")}, "203.0.113.7/32"},
		{"v4-mapped", DialGuard{}, openAll, DialTarget{Addr: ap("[::ffff:10.96.0.1]:443")}, "10.96.0.1/32"},
		{"its neighbour is only private", DialGuard{}, openAll, DialTarget{Addr: ap("10.96.0.2:443")}, ""},
		{"a public neighbour", DialGuard{}, nil, DialTarget{Addr: ap("203.0.113.8:443")}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.guard.Check(tc.policy, tc.target)
			if tc.rule == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			var de *DialError
			if !errors.As(err, &de) || de.Reason != DialReasonDenyFloor || de.Rule != tc.rule {
				t.Fatalf("err = %#v, want the floor's %s", err, tc.rule)
			}
			// The WASM mediator's no-policy dials use the floor alone.
			if err := tc.guard.CheckFloor(tc.target.Addr); !errors.Is(err, ErrDialRefused) {
				t.Fatalf("CheckFloor passed %s", tc.target.Addr)
			}
		})
	}
	// The host firewall and the gateway's kernel set get the same floor.
	got := WithFixedFloor([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("10.96.0.1/32")})
	want := append([]netip.Prefix{netip.MustParsePrefix("10.20.0.0/16"), netip.MustParsePrefix("10.96.0.1/32")}, MetadataPrefixes...)
	want = append(want, netip.MustParsePrefix("172.18.0.2/32"), netip.MustParsePrefix("203.0.113.7/32"))
	if !slices.Equal(got, want) {
		t.Fatalf("WithFixedFloor = %v, want %v", got, want)
	}
}

// TestExtraPrivateRanges (C24): the node's extra private ranges are refused
// by default like RFC 1918, and a policy CIDR allow (an egress profile)
// opens one on purpose, and only it. Isolate's strict guard never opens
// them, as for RFC 1918 (D15).
func TestExtraPrivateRanges(t *testing.T) {
	withRanges(t, "", "198.18.0.0/15, 2001:db8:10::/64")
	opened := mustCompile(t, Spec{AllowOut: []string{"198.18.4.0/24"}})
	nameOnly := mustCompile(t, Spec{AllowOut: []string{"svc.example.com"}})
	denyOther := mustCompile(t, Spec{DenyOut: []string{"203.0.113.0/24"}})
	tests := []struct {
		name   string
		guard  DialGuard
		policy *Policy
		target DialTarget
		reason string // "" = allowed
	}{
		{"no policy", DialGuard{}, nil, DialTarget{Addr: ap("198.18.0.10:443")}, DialReasonPrivate},
		{"IPv6 range, no policy", DialGuard{}, nil, DialTarget{Addr: ap("[2001:db8:10::5]:443")}, DialReasonPrivate},
		{"a policy that names other things", DialGuard{}, denyOther, DialTarget{Addr: ap("198.18.0.10:443")}, DialReasonPrivate},
		{"an allowed name resolving into it", DialGuard{}, nameOnly, DialTarget{Name: "svc.example.com", NameAllowed: true, Addr: ap("198.19.0.1:443")}, DialReasonPrivate},
		{"the opened range", DialGuard{}, opened, DialTarget{Addr: ap("198.18.4.20:5432")}, ""},
		{"the rest of the range stays shut", DialGuard{}, opened, DialTarget{Addr: ap("198.18.5.20:5432")}, DialReasonPrivate},
		{"strict ignores the allow", DialGuard{Strict: true}, opened, DialTarget{Addr: ap("198.18.4.20:5432")}, DialReasonPrivate},
		{"outside every range", DialGuard{}, nil, DialTarget{Addr: ap("198.20.0.1:443")}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.guard.Check(tc.policy, tc.target)
			if tc.reason == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			var de *DialError
			if !errors.As(err, &de) || de.Reason != tc.reason {
				t.Fatalf("err = %#v, want reason %q", err, tc.reason)
			}
		})
	}
	// Private, not floor: the floor's checks never see these ranges.
	if err := (DialGuard{}).CheckFloor(ap("198.18.0.10:443")); err != nil {
		t.Fatalf("an extra private range is on the floor: %v", err)
	}
}
