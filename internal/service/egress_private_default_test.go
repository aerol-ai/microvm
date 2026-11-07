package service

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
	"github.com/aerol-ai/microvm/pkg/models"
)

// withResolvConfs points the resolver files EnableBlockPrivateByDefault and
// the node guard read at temp files holding bodies.
func withResolvConfs(t *testing.T, bodies ...string) {
	t.Helper()
	old := nodeGuardResolvConfs
	t.Cleanup(func() { nodeGuardResolvConfs = old })
	nodeGuardResolvConfs = nil
	for i, body := range bodies {
		p := filepath.Join(t.TempDir(), "resolv"+string(rune('a'+i))+".conf")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		nodeGuardResolvConfs = append(nodeGuardResolvConfs, p)
	}
}

func TestPrivateDefaultResolverAllow(t *testing.T) {
	var addrs []netip.Addr
	for _, s := range []string{
		"172.31.0.2",      // AWS default-VPC resolver: inside 172.16/12
		"10.0.0.2",        // custom-VPC resolver
		"10.0.0.2",        // listed in both files
		"8.8.8.8",         // public: nothing to open
		"169.254.169.253", // Amazon DNS on link-local
		"169.254.169.254", // GCP's resolver is the metadata address: the floor drops it anyway
		"127.0.0.53",      // a loopback stub never reaches a sandbox
		"fd00::53",        // no IPv6 in a sandbox
		"::ffff:192.168.1.1",
	} {
		addrs = append(addrs, netip.MustParseAddr(s))
	}
	got := privateDefaultResolverAllow(addrs)
	want := []string{"10.0.0.2/32", "169.254.169.253/32", "172.31.0.2/32", "192.168.1.1/32"}
	if !slices.Equal(got, want) {
		t.Fatalf("allow = %v, want %v", got, want)
	}
	if privateDefaultResolverAllow(nil) != nil {
		t.Fatal("no resolvers, no allow entries")
	}
}

// TestPrivateDefaultPolicyShape: the default compiles and keeps the
// resolver reachable while the rest of each private range is denied and the
// internet stays open (allow wins, then deny, then accept).
func TestPrivateDefaultPolicyShape(t *testing.T) {
	pol, err := egresspolicy.Compile(egresspolicy.Spec{AllowOut: []string{"172.31.0.2/32"}, DenyOut: privateDefaultDeny})
	if err != nil {
		t.Fatalf("the default must compile: %v", err)
	}
	if pol.GatewayMode() {
		t.Fatal("an address-only default must not need the egress gateway")
	}
	if egresspolicy.NeedsGatewayWith([]string{"172.31.0.2/32"}, privateDefaultDeny, false, false, 0) {
		t.Fatal("placement must not send the default to gateway nodes only")
	}
}

func TestEnableBlockPrivateByDefaultReadsResolvers(t *testing.T) {
	withResolvConfs(t, "nameserver 127.0.0.53\n", "nameserver 172.31.0.2\nnameserver 1.1.1.1\n")
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if svc.blockPrivateDefault.Load() != nil {
		t.Fatal("off until enabled")
	}
	svc.EnableBlockPrivateByDefault()
	pd := svc.blockPrivateDefault.Load()
	if pd == nil || !slices.Equal(pd.allow, []string{"172.31.0.2/32"}) {
		t.Fatalf("state = %+v, want the private resolver open", pd)
	}
}

// TestPrivateDefaultOnOffAndExplicitPolicies walks the flag through create:
// off changes nothing; on gives a no-policy create the deny list with its
// resolver open, stored on the row and handed to the runtime; a create that
// sets any policy keeps exactly its own.
func TestPrivateDefaultOnOffAndExplicitPolicies(t *testing.T) {
	cases := []struct {
		name      string
		on        bool
		req       models.CreateSandboxRequest
		wantAllow []string
		wantDeny  []string
		wantBlock bool
	}{
		{name: "off", req: models.CreateSandboxRequest{Image: "alpine"}},
		{name: "on, no policy", on: true, req: models.CreateSandboxRequest{Image: "alpine"}, wantAllow: []string{"10.0.0.2/32"}, wantDeny: privateDefaultDeny},
		{name: "on, firecracker runtime", on: true, req: models.CreateSandboxRequest{Image: "alpine", Runtime: models.RuntimeFirecracker}, wantAllow: []string{"10.0.0.2/32"}, wantDeny: privateDefaultDeny},
		{name: "on, explicit allow list", on: true, req: models.CreateSandboxRequest{Image: "alpine", NetworkAllowOut: []string{"10.9.0.0/16"}}, wantAllow: []string{"10.9.0.0/16"}},
		{name: "on, explicit deny list", on: true, req: models.CreateSandboxRequest{Image: "alpine", NetworkDenyOut: []string{"203.0.113.0/24"}}, wantDeny: []string{"203.0.113.0/24"}},
		{name: "on, block all", on: true, req: models.CreateSandboxRequest{Image: "alpine", NetworkBlockAll: true}, wantBlock: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withResolvConfs(t, "nameserver 10.0.0.2\n")
			rt := &recordingRuntime{}
			svc, _, _ := newServiceRuntimeHarness(t, rt)
			svc.cfg.EnableFirecracker = false
			if tc.on {
				svc.EnableBlockPrivateByDefault()
			}
			req := tc.req
			svc.NormalizeCreateEgressDefault(&req)
			if !slices.Equal(req.NetworkAllowOut, tc.wantAllow) || !slices.Equal(req.NetworkDenyOut, tc.wantDeny) || req.NetworkBlockAll != tc.wantBlock {
				t.Fatalf("normalized = allow %v deny %v block %v; want %v %v %v", req.NetworkAllowOut, req.NetworkDenyOut, req.NetworkBlockAll, tc.wantAllow, tc.wantDeny, tc.wantBlock)
			}
			if tc.req.Runtime == models.RuntimeFirecracker {
				return // the harness has no Firecracker driver; normalization is what is under test
			}
			resp, err := svc.CreateSandbox(context.Background(), tc.req)
			if err != nil {
				t.Fatal(err)
			}
			sb, err := svc.store.Get(context.Background(), resp.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(sb.NetworkAllowOut, tc.wantAllow) || !slices.Equal(sb.NetworkDenyOut, tc.wantDeny) {
				t.Fatalf("stored = allow %v deny %v; want %v %v", sb.NetworkAllowOut, sb.NetworkDenyOut, tc.wantAllow, tc.wantDeny)
			}
			if !slices.Equal(rt.lastCreateReq.NetworkDenyOut, tc.wantDeny) {
				t.Fatalf("runtime got deny %v, want %v", rt.lastCreateReq.NetworkDenyOut, tc.wantDeny)
			}
		})
	}
}

// TestPrivateDefaultSkips: WASM and isolate filter in their own mediators;
// the operator file's default wins when it sets one; a failover replay keeps
// the spec it was given.
func TestPrivateDefaultSkips(t *testing.T) {
	withResolvConfs(t, "nameserver 10.0.0.2\n")
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.EnableBlockPrivateByDefault()
	for _, rt := range []string{models.RuntimeWasm, models.RuntimeIsolate} {
		req := models.CreateSandboxRequest{Runtime: rt}
		svc.NormalizeCreateEgressDefault(&req)
		if hasEgressFields(&req) {
			t.Fatalf("%s got %v %v", rt, req.NetworkAllowOut, req.NetworkDenyOut)
		}
	}

	svc.SetEgressOperator(operatorWatcher(t, "version: 1\ndefault_policy: {mode: block_all}\n"))
	req := models.CreateSandboxRequest{}
	svc.NormalizeCreateEgressDefault(&req)
	if !req.NetworkBlockAll || len(req.NetworkDenyOut) != 0 {
		t.Fatalf("operator default must win: block %v deny %v", req.NetworkBlockAll, req.NetworkDenyOut)
	}
	svc.SetEgressOperator(nil)

	rt := &recordingRuntime{}
	replaySvc, _, _ := newServiceRuntimeHarness(t, rt)
	replaySvc.EnableBlockPrivateByDefault()
	ctx := contextWithStoredSpecReplay(context.Background())
	if _, err := replaySvc.CreateSandboxWithID(ctx, models.CreateSandboxRequest{Image: "alpine"}, "sb-00000000000000a4"); err != nil {
		t.Fatal(err)
	}
	if len(rt.lastCreateReq.NetworkDenyOut) != 0 {
		t.Fatal("a replay must not pick up a default its first create did not have")
	}
}

// TestPrivateDefaultRulesAndTeardown runs the default through the real rule
// manager: the sandbox reaches the internet and its resolver but not the rest
// of a private range or link-local, and its destroy removes every rule it had.
func TestPrivateDefaultRulesAndTeardown(t *testing.T) {
	withResolvConfs(t, "nameserver 10.0.0.2\n")
	svc, rt, be := firewallHarness(t)
	svc.EnableBlockPrivateByDefault()
	ctx := context.Background()
	req := models.CreateSandboxRequest{Image: "alpine"}
	svc.NormalizeCreateEgressDefault(&req)
	sb := seedPolicySandbox(t, svc, models.Sandbox{ID: "sb-t4", NetworkAllowOut: req.NetworkAllowOut, NetworkDenyOut: req.NetworkDenyOut, AuditIncarnationID: "t4"})
	// What the runtime installs at create from the same lists.
	if err := rt.ApplyEgressPolicy(policyIP, sb.NetworkAllowOut, sb.NetworkDenyOut); err != nil {
		t.Fatal(err)
	}
	for dst, want := range map[string]bool{
		"1.1.1.1":         true,  // the internet stays open
		"10.0.0.2":        true,  // its own resolver
		"10.0.0.3":        false, // the rest of 10/8
		"172.20.1.1":      false,
		"192.168.1.10":    false,
		"169.254.169.253": false,
	} {
		if got := be.permits(policyIP, dst); got != want {
			t.Errorf("permits(%s) = %v, want %v", dst, got, want)
		}
	}
	if err := svc.DestroySandbox(ctx, sb.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.store.Get(ctx, sb.ID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("row after destroy: %v", err)
	}
	for _, rule := range be["filter"+netrules.ChainDockerUser] {
		if slices.Contains(rule, policyIP) {
			t.Fatalf("rule left behind after destroy: %v", rule)
		}
	}
}
