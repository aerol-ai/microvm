package egresspolicy

import (
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// obs is one observation fed to a Recorder, so a table can describe a run
// independent of which runtime produced it (EF-76).
type obs struct {
	kind    string // "dns", "host", "flow"
	name    string
	ips     []string
	port    uint16
	flowIP  string
	repeats int
}

func feed(r *Recorder, observations []obs) {
	for _, o := range observations {
		for i := 0; i <= o.repeats; i++ {
			switch o.kind {
			case "dns":
				var ips []netip.Addr
				for _, s := range o.ips {
					ips = append(ips, netip.MustParseAddr(s))
				}
				r.ObserveDNS(o.name, ips)
			case "host":
				r.ObserveHost(o.name, o.port)
			case "flow":
				r.ObserveFlow(netip.MustParseAddr(o.flowIP), o.port)
			}
		}
	}
}

// TestRecorderSuggestions is the one table test for learn-mode suggestions
// (eng re-review S7): every runtime feeds this type, so this is the contract.
func TestRecorderSuggestions(t *testing.T) {
	tests := []struct {
		name  string
		feed  []obs
		want  []string
		cidrs []string
	}{
		{
			name: "pip_install",
			feed: []obs{
				{kind: "dns", name: "pypi.org", ips: []string{"151.101.0.223"}},
				{kind: "host", name: "pypi.org", port: 443},
				{kind: "dns", name: "files.pythonhosted.org.", ips: []string{"151.101.1.63"}},
				{kind: "host", name: "Files.PythonHosted.org", port: 443},
			},
			want: []string{"files.pythonhosted.org", "pypi.org"},
		},
		{
			name: "three_subdomains_collapse",
			feed: []obs{
				{kind: "host", name: "a.example.com", port: 443},
				{kind: "host", name: "b.example.com", port: 80},
				{kind: "host", name: "c.d.example.com", port: 443},
			},
			want: []string{"*.example.com"},
		},
		{
			name: "apex_kept_exact_beside_wildcard",
			feed: []obs{
				{kind: "host", name: "example.com", port: 443},
				{kind: "host", name: "a.example.com", port: 443},
				{kind: "host", name: "b.example.com", port: 443},
			},
			want: []string{"*.example.com", "example.com"},
		},
		{
			name: "two_subdomains_stay_exact",
			feed: []obs{
				{kind: "host", name: "a.example.com", port: 443},
				{kind: "host", name: "b.example.com", port: 443},
			},
			want: []string{"a.example.com", "b.example.com"},
		},
		{
			name: "never_collapse_onto_a_public_suffix",
			feed: []obs{
				{kind: "host", name: "alice.github.io", port: 443},
				{kind: "host", name: "bob.github.io", port: 443},
				{kind: "host", name: "carol.github.io", port: 443},
			},
			want: []string{"alice.github.io", "bob.github.io", "carol.github.io"},
		},
		{
			name: "collapse_below_a_private_suffix",
			feed: []obs{
				{kind: "host", name: "a.docs.github.io", port: 443},
				{kind: "host", name: "b.docs.github.io", port: 443},
				{kind: "host", name: "c.docs.github.io", port: 443},
			},
			want: []string{"*.docs.github.io"},
		},
		{
			name: "dns_correlated_flow_becomes_host_port",
			feed: []obs{
				{kind: "dns", name: "github.com", ips: []string{"140.82.112.3"}},
				{kind: "flow", flowIP: "140.82.112.3", port: 22},
			},
			want: []string{"github.com:22"},
		},
		{
			name: "web_and_other_port_on_one_host",
			feed: []obs{
				{kind: "dns", name: "github.com", ips: []string{"140.82.112.3"}},
				{kind: "host", name: "github.com", port: 443},
				{kind: "flow", flowIP: "::ffff:140.82.112.3", port: 22},
			},
			want: []string{"github.com", "github.com:22"},
		},
		{
			name: "port_entries_collapse_per_port",
			feed: []obs{
				{kind: "dns", name: "a.git.example.com", ips: []string{"203.0.113.1"}},
				{kind: "dns", name: "b.git.example.com", ips: []string{"203.0.113.2"}},
				{kind: "dns", name: "c.git.example.com", ips: []string{"203.0.113.3"}},
				{kind: "flow", flowIP: "203.0.113.1", port: 22},
				{kind: "flow", flowIP: "203.0.113.2", port: 22},
				{kind: "flow", flowIP: "203.0.113.3", port: 22},
				{kind: "flow", flowIP: "203.0.113.3", port: 2222},
			},
			want: []string{"*.example.com:22", "c.git.example.com:2222"},
		},
		{
			name: "unnamed_flows_become_single_address_cidrs",
			feed: []obs{
				{kind: "flow", flowIP: "203.0.113.7", port: 5432},
				{kind: "flow", flowIP: "2001:db8::7", port: 5432},
				{kind: "host", name: "198.51.100.9", port: 443}, // IP-literal SNI/Host
			},
			want:  []string{"198.51.100.9/32", "2001:db8::7/128", "203.0.113.7/32"},
			cidrs: []string{"198.51.100.9/32", "203.0.113.7/32", "2001:db8::7/128"},
		},
		{
			name: "dns_only_name_still_resolves",
			feed: []obs{{kind: "dns", name: "telemetry.example.org"}},
			want: []string{"telemetry.example.org"},
		},
		{
			name: "garbage_ignored_and_ungrammatical_names_not_suggested",
			feed: []obs{
				{kind: "host", name: "bad name", port: 443},
				{kind: "dns", name: ""},
				{kind: "host", name: "-lead.example.net", port: 443},
				{kind: "host", name: "ok.example.net", port: 443},
			},
			want: []string{"ok.example.net"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewRecorder(0)
			feed(r, tc.feed)
			got := r.Snapshot()
			if strings.Join(got.SuggestedAllowOut, ",") != strings.Join(tc.want, ",") || got.SuggestedProfile != nil {
				t.Fatalf("suggested %v (profile %v), want %v", got.SuggestedAllowOut, got.SuggestedProfile, tc.want)
			}
			if tc.cidrs != nil && strings.Join(got.CIDRs, ",") != strings.Join(tc.cidrs, ",") {
				t.Fatalf("cidrs %v, want %v", got.CIDRs, tc.cidrs)
			}
			// A suggestion must always be a valid inline policy.
			if _, err := Compile(Spec{AllowOut: got.SuggestedAllowOut}); err != nil {
				t.Fatalf("suggestion does not compile: %v", err)
			}
		})
	}
}

// TestRecorderOrderIndependent proves identical traffic gives identical
// suggestions however a runtime interleaves it (EF-76).
func TestRecorderOrderIndependent(t *testing.T) {
	feedA := []obs{
		{kind: "dns", name: "github.com", ips: []string{"140.82.112.3"}},
		{kind: "host", name: "a.example.com", port: 443},
		{kind: "flow", flowIP: "140.82.112.3", port: 22},
		{kind: "host", name: "b.example.com", port: 443},
		{kind: "host", name: "c.example.com", port: 443},
		{kind: "flow", flowIP: "203.0.113.7", port: 5432},
	}
	feedB := []obs{feedA[5], feedA[4], feedA[0], feedA[3], feedA[2], feedA[1]}
	a, b := NewRecorder(0), NewRecorder(0)
	feed(a, feedA)
	feed(b, feedB)
	sa, sb := a.Snapshot(), b.Snapshot()
	if fmt.Sprint(sa.SuggestedAllowOut) != fmt.Sprint(sb.SuggestedAllowOut) || fmt.Sprint(sa.CIDRs) != fmt.Sprint(sb.CIDRs) {
		t.Fatalf("order changed the suggestion: %v vs %v", sa.SuggestedAllowOut, sb.SuggestedAllowOut)
	}
}

func TestRecorderEntriesAndClock(t *testing.T) {
	r := NewRecorder(0)
	t0 := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	now := t0
	r.now = func() time.Time { return now }
	r.ObserveDNS("pypi.org", []netip.Addr{netip.MustParseAddr("151.101.0.223"), {}})
	now = now.Add(time.Second)
	r.ObserveHost("pypi.org", 443)
	r.ObserveFlow(netip.Addr{}, 22) // invalid IP ignored
	got := r.Snapshot()
	if len(got.Entries) != 1 {
		t.Fatalf("entries = %+v", got.Entries)
	}
	e := got.Entries[0]
	if e.Host != "pypi.org" || fmt.Sprint(e.Ports) != "[443]" || e.Hits != 2 || !e.FirstSeen.Equal(t0) || !e.LastSeen.Equal(t0.Add(time.Second)) {
		t.Fatalf("entry = %+v", e)
	}
	if got.Truncated || len(got.CIDRs) != 0 {
		t.Fatalf("snapshot = %+v", got)
	}
}

func TestRecorderCaps(t *testing.T) {
	t.Run("destination_cap_truncates_new_keeps_counting_old", func(t *testing.T) {
		r := NewRecorder(2)
		r.ObserveHost("a.example.org", 443)
		r.ObserveFlow(netip.MustParseAddr("203.0.113.7"), 22)
		r.ObserveHost("b.example.org", 443) // third destination: dropped
		r.ObserveHost("a.example.org", 443)
		got := r.Snapshot()
		if !got.Truncated || len(got.Entries) != 1 || len(got.CIDRs) != 1 || got.Entries[0].Hits != 2 {
			t.Fatalf("snapshot = %+v", got)
		}
	})
	t.Run("correlation_map_is_bounded", func(t *testing.T) {
		r := NewRecorder(1)
		var ips []netip.Addr
		for i := 1; i <= 5; i++ {
			ips = append(ips, netip.AddrFrom4([4]byte{203, 0, 113, byte(i)}))
		}
		r.ObserveDNS("cdn.example.org", ips)
		if !r.Snapshot().Truncated || len(r.ipName) != 4 {
			t.Fatalf("ipName = %d entries", len(r.ipName))
		}
	})
	t.Run("over_inline_cap_becomes_a_profile", func(t *testing.T) {
		r := NewRecorder(0)
		for i := 0; i <= MaxInlineHostnames; i++ {
			r.ObserveHost(fmt.Sprintf("site%d.org", i), 443)
		}
		r.ObserveFlow(netip.MustParseAddr("203.0.113.7"), 5432)
		got := r.Snapshot()
		if got.SuggestedProfile == nil || len(got.SuggestedAllowOut) != 0 || got.Truncated {
			t.Fatalf("snapshot = %+v", got)
		}
		if _, err := ParseAllowList("allow_out", got.SuggestedProfile.AllowOut, MaxProfileHostnames); err != nil {
			t.Fatalf("profile body invalid: %v", err)
		}
		if len(got.SuggestedProfile.AllowOut) != MaxInlineHostnames+2 || !strings.Contains(got.SuggestedProfile.Description, "66 observed") {
			t.Fatalf("profile = %+v", got.SuggestedProfile)
		}
	})
	t.Run("at_inline_cap_stays_inline", func(t *testing.T) {
		r := NewRecorder(0)
		for i := 0; i < MaxInlineHostnames; i++ {
			r.ObserveHost(fmt.Sprintf("site%d.org", i), 443)
		}
		if got := r.Snapshot(); got.SuggestedProfile != nil || len(got.SuggestedAllowOut) != MaxInlineHostnames {
			t.Fatalf("snapshot = %+v", got)
		}
	})
	t.Run("over_profile_cap_is_cut_and_reported", func(t *testing.T) {
		r := NewRecorder(0)
		for i := 0; i < MaxProfileHostnames+40; i++ {
			r.ObserveHost(fmt.Sprintf("site%d.org", i), 443)
		}
		r.ObserveFlow(netip.MustParseAddr("203.0.113.7"), 5432)
		got := r.Snapshot()
		if !got.Truncated || got.SuggestedProfile == nil {
			t.Fatalf("snapshot truncated=%v profile=%v", got.Truncated, got.SuggestedProfile != nil)
		}
		entries, err := ParseAllowList("allow_out", got.SuggestedProfile.AllowOut, MaxProfileHostnames)
		if err != nil || CountHostnames(entries) != MaxProfileHostnames || len(entries) != MaxProfileHostnames+1 {
			t.Fatalf("cut profile: %d entries, %v", len(entries), err)
		}
	})
}

func TestRecorderConcurrent(t *testing.T) {
	r := NewRecorder(0)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				ip := netip.AddrFrom4([4]byte{203, 0, byte(g), byte(i)})
				r.ObserveDNS(fmt.Sprintf("h%d.g%d.example.net", i, g), []netip.Addr{ip})
				r.ObserveFlow(ip, 22)
				r.ObserveHost(fmt.Sprintf("h%d.g%d.example.net", i, g), 443)
				_ = r.Snapshot()
			}
		}(g)
	}
	wg.Wait()
	got := r.Snapshot()
	if len(got.Entries) != 800 || got.Truncated {
		t.Fatalf("entries = %d truncated = %v", len(got.Entries), got.Truncated)
	}
	for _, e := range got.Entries {
		if e.Hits != 3 || fmt.Sprint(e.Ports) != "[22 443]" {
			t.Fatalf("entry = %+v", e)
		}
	}
}
