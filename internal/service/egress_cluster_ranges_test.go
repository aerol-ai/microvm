package service

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// withEgressRanges installs the node's extra deny floor and private ranges
// for one test (they are process-wide) and puts the old ones back.
func withEgressRanges(t *testing.T, floor, private []netip.Prefix) {
	t.Helper()
	prevFloor, prevPrivate := egresspolicy.ExtraDenyFloor(), egresspolicy.ExtraPrivateRanges()
	t.Cleanup(func() { egresspolicy.SetRanges(prevFloor, prevPrivate) })
	egresspolicy.SetRanges(floor, private)
}

func prefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// TestEgressFloorCarriesTheAPIServer (C24): the extra deny floor goes into
// the host-firewall floor of every container and Firecracker runtime, with
// or without an operator file, next to the metadata endpoints.
func TestEgressFloorCarriesTheAPIServer(t *testing.T) {
	ctx := context.Background()
	withEgressRanges(t, prefixes("10.96.0.1/32", "172.18.0.2/32"), nil)
	svc, dockerRT, ctdRT, fcRT, _ := newFloorService()

	svc.ApplyEgressFloor(ctx)
	want := append(slices.Clone(egresspolicy.MetadataPrefixes), prefixes("10.96.0.1/32", "172.18.0.2/32")...)
	for name, rt := range map[string]*floorRuntime{"docker": dockerRT, "containerd": ctdRT, "firecracker": fcRT} {
		if len(rt.floor) == 0 || !slices.Equal(rt.floor[len(rt.floor)-1], want) {
			t.Fatalf("%s floor = %v, want %v", name, rt.floor, want)
		}
	}

	svc.OnEgressOperatorChange(operatorWatcher(t, "version: 1\ndeny_cidrs: [10.20.0.0/16]\n").Current())
	want = append(prefixes("10.20.0.0/16"), want...)
	if last := dockerRT.floor[len(dockerRT.floor)-1]; !slices.Equal(last, want) {
		t.Fatalf("with an operator file the floor = %v, want %v", last, want)
	}
}

// TestPrivateDefaultExtraRanges (C24): the cluster's ranges join the
// private-range default a no-policy create gets (IPv4 only, each once), a
// resolver inside one stays open, and the WASM and isolate runtimes are
// still left to their own guards.
func TestPrivateDefaultExtraRanges(t *testing.T) {
	withResolvConfs(t, "nameserver 198.18.0.10\nnameserver 10.0.0.2\n")
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EgressPrivateDefaultCIDRs = prefixes("198.18.0.0/15", "10.244.0.0/16", "10.0.0.0/8", "2001:db8::/32")
	svc.EnableBlockPrivateByDefault()

	wantDeny := append(slices.Clone(privateDefaultDeny), "198.18.0.0/15", "10.244.0.0/16")
	wantAllow := []string{"10.0.0.2/32", "198.18.0.10/32"}
	req := models.CreateSandboxRequest{Image: "alpine"}
	svc.NormalizeCreateEgressDefault(&req)
	if !slices.Equal(req.NetworkDenyOut, wantDeny) || !slices.Equal(req.NetworkAllowOut, wantAllow) {
		t.Fatalf("default = deny %v allow %v; want %v %v", req.NetworkDenyOut, req.NetworkAllowOut, wantDeny, wantAllow)
	}
	// The default compiles as the policy it is: allow wins, then deny, then
	// the internet stays open.
	pol, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: req.NetworkAllowOut, DenyOut: req.NetworkDenyOut})
	if err != nil {
		t.Fatal(err)
	}
	for dst, want := range map[string]bool{"198.18.0.10": true, "198.19.1.1": false, "10.244.3.4": false, "1.1.1.1": true} {
		if got, _ := pol.MatchIP(netip.MustParseAddr(dst), 443); got != want {
			t.Errorf("%s allowed = %v, want %v", dst, got, want)
		}
	}
	// A create with its own policy (an egress profile) keeps exactly it.
	own := models.CreateSandboxRequest{Image: "alpine", EgressProfiles: []string{"bank-api"}}
	svc.NormalizeCreateEgressDefault(&own)
	if own.NetworkDenyOut != nil || own.NetworkAllowOut != nil {
		t.Fatalf("an explicit policy got the default: %v %v", own.NetworkDenyOut, own.NetworkAllowOut)
	}
	wasm := models.CreateSandboxRequest{Runtime: models.RuntimeWasm}
	svc.NormalizeCreateEgressDefault(&wasm)
	if hasEgressFields(&wasm) {
		t.Fatalf("WASM got a host-firewall default: %v", wasm.NetworkDenyOut)
	}
}

// TestPrivateDefaultResolverOnTheFloor: a resolver on the extra floor gets
// no allow entry, since the floor drops it anyway (GET must not show an
// allow that is not real).
func TestPrivateDefaultResolverOnTheFloor(t *testing.T) {
	withEgressRanges(t, prefixes("10.96.0.10/32"), nil)
	got := privateDefaultResolverAllow([]netip.Addr{netip.MustParseAddr("10.96.0.10"), netip.MustParseAddr("10.96.0.11")}, privateDefaultDeny)
	if !slices.Equal(got, []string{"10.96.0.11/32"}) {
		t.Fatalf("allow = %v", got)
	}
}

// TestOpenedClusterRangeRules (C24): on the real rule manager a default
// sandbox cannot reach an extra private range, and a sandbox whose profile
// opens one part of it reaches that part and nothing else.
func TestOpenedClusterRangeRules(t *testing.T) {
	withResolvConfs(t, "nameserver 10.0.0.2\n")
	svc, rt, be := firewallHarness(t)
	svc.cfg.EgressPrivateDefaultCIDRs = prefixes("198.18.0.0/15")
	svc.EnableBlockPrivateByDefault()
	req := models.CreateSandboxRequest{Image: "alpine"}
	svc.NormalizeCreateEgressDefault(&req)
	if err := rt.ApplyEgressPolicy(policyIP, req.NetworkAllowOut, req.NetworkDenyOut); err != nil {
		t.Fatal(err)
	}
	for dst, want := range map[string]bool{"198.18.4.20": false, "198.19.0.1": false, "10.0.0.2": true, "1.1.1.1": true} {
		if got := be.permits(policyIP, dst); got != want {
			t.Errorf("default sandbox permits(%s) = %v, want %v", dst, got, want)
		}
	}
	if err := rt.ClearEgressPolicy(policyIP, req.NetworkAllowOut, req.NetworkDenyOut); err != nil {
		t.Fatal(err)
	}
	// The profile's list is what the sandbox gets: an allow list.
	if err := rt.ApplyEgressPolicy(policyIP, []string{"198.18.4.0/24"}, nil); err != nil {
		t.Fatal(err)
	}
	for dst, want := range map[string]bool{"198.18.4.20": true, "198.18.5.20": false, "10.0.0.3": false} {
		if got := be.permits(policyIP, dst); got != want {
			t.Errorf("opened sandbox permits(%s) = %v, want %v", dst, got, want)
		}
	}
}
