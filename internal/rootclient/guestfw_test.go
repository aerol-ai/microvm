package rootclient

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"testing"

	"google.golang.org/grpc/codes"

	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
)

// guestHelper serves the guests' firewall calls (M1 PR 14) and records
// them; features is what its handshake lists.
type guestHelper struct {
	rootdpb.UnimplementedRootHelperServer
	features []string
	mu       sync.Mutex
	calls    []string
}

func (h *guestHelper) note(s string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, s)
}

func (h *guestHelper) seen() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.calls)
}

func (h *guestHelper) Version(context.Context, *rootdpb.VersionRequest) (*rootdpb.VersionResponse, error) {
	return &rootdpb.VersionResponse{HelperVersion: "n", Api: rootdpb.APIVersion, Features: h.features}, nil
}

func (h *guestHelper) EnsureGuestFirewall(context.Context, *rootdpb.EnsureGuestFirewallRequest) (*rootdpb.EnsureGuestFirewallResponse, error) {
	h.note("ensure")
	return &rootdpb.EnsureGuestFirewallResponse{}, nil
}

func (h *guestHelper) SetGuestNodeGuard(_ context.Context, req *rootdpb.SetNodeGuardRequest) (*rootdpb.SetNodeGuardResponse, error) {
	h.note(fmt.Sprintf("guard %d", len(req.GetAllow())))
	return &rootdpb.SetNodeGuardResponse{Repaired: true}, nil
}

func (h *guestHelper) SetGuestEgressFloor(_ context.Context, req *rootdpb.SetEgressFloorRequest) (*rootdpb.SetEgressFloorResponse, error) {
	h.note(fmt.Sprintf("floor %v", req.GetCidrs()))
	return &rootdpb.SetEgressFloorResponse{Repaired: true}, nil
}

func (h *guestHelper) GuestRules(_ context.Context, req *rootdpb.GuestRulesRequest) (*rootdpb.GuestRulesResponse, error) {
	if req.GetGuestIp() == "172.16.0.13" {
		return nil, rootdpb.Refused(codes.InvalidArgument, "address", "a TAP's host end")
	}
	h.note(fmt.Sprintf("%v %s %v %v", req.GetOp(), req.GetGuestIp(), req.GetAllowCidrs(), req.GetDenyCidrs()))
	return &rootdpb.GuestRulesResponse{Inserted: true}, nil
}

func (h *guestHelper) EnsureHost(context.Context, *rootdpb.EnsureHostRequest) (*rootdpb.EnsureHostResponse, error) {
	return &rootdpb.EnsureHostResponse{Ipv6FenceError: "bridge", FencesFirecracker: true, FirecrackerIpv6FenceError: "taps"}, nil
}

// TestEnsureHostFences: the host step's answer carries the fence's state
// on the bridge and on the TAPs.
func TestEnsureHostFences(t *testing.T) {
	h := &guestHelper{features: rootdpb.Features()}
	sock := newOwnedSocket(t)
	sock.serve(t, h)
	c := New(Config{Socket: sock.path, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = c.Close() })
	f, err := c.EnsureHostFences(ctxT(t))
	if err != nil || f != (Fences{Containerd: "bridge", Firecracker: "taps", CoversFirecracker: true}) {
		t.Fatalf("EnsureHostFences = %+v, %v", f, err)
	}
	if fence, err := c.EnsureHostFirewall(ctxT(t)); err != nil || fence != "bridge" {
		t.Fatalf("EnsureHostFirewall = %q, %v", fence, err)
	}
}

// TestGuestFirewallCalls: each guest firewall call reaches the helper with
// what it was given and brings back its answer; a refusal is a refusal.
func TestGuestFirewallCalls(t *testing.T) {
	h := &guestHelper{features: rootdpb.Features()}
	sock := newOwnedSocket(t)
	sock.serve(t, h)
	c := New(Config{Socket: sock.path, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = c.Close() })
	ctx := ctxT(t)
	if err := c.EnsureGuestFirewall(ctx); err != nil {
		t.Fatal(err)
	}
	if rep, err := c.SetGuestNodeGuard(ctx, []*rootdpb.NodePort{{Proto: "tcp", Port: 15080}}); err != nil || !rep {
		t.Fatalf("SetGuestNodeGuard = %v, %v", rep, err)
	}
	if rep, err := c.SetGuestEgressFloor(ctx, []string{"10.20.0.0/16"}); err != nil || !rep {
		t.Fatalf("SetGuestEgressFloor = %v, %v", rep, err)
	}
	if ins, err := c.GuestRules(ctx, rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_APPLY_EGRESS_POLICY, "172.16.0.14", []string{"1.2.3.4/32"}, nil); err != nil || !ins {
		t.Fatalf("GuestRules = %v, %v", ins, err)
	}
	want := []string{"ensure", "guard 1", "floor [10.20.0.0/16]", "SANDBOX_RULES_OP_APPLY_EGRESS_POLICY 172.16.0.14 [1.2.3.4/32] []"}
	if got := h.seen(); !slices.Equal(got, want) {
		t.Fatalf("calls %q, want %q", got, want)
	}
	if _, err := c.GuestRules(ctx, rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS, "172.16.0.13", nil, nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("a refused address = %v", err)
	}
}

// TestGuestFirewallCallsTheHelperLacks: an older helper, whose handshake
// lists no guest firewall call, is sent none, and each answers
// ErrUnsupported, which the agent turns into a refusal to start.
func TestGuestFirewallCallsTheHelperLacks(t *testing.T) {
	old := slices.DeleteFunc(rootdpb.Features(), func(f string) bool {
		return f == rootdpb.FeatureEnsureGuestFirewall || f == rootdpb.FeatureSetGuestNodeGuard ||
			f == rootdpb.FeatureSetGuestEgressFloor || f == rootdpb.FeatureGuestRules
	})
	h := &guestHelper{features: old}
	sock := newOwnedSocket(t)
	sock.serve(t, h)
	c := New(Config{Socket: sock.path, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = c.Close() })
	ctx := ctxT(t)
	for _, call := range []func() error{
		func() error { return c.EnsureGuestFirewall(ctx) },
		func() error { _, err := c.SetGuestNodeGuard(ctx, nil); return err },
		func() error { _, err := c.SetGuestEgressFloor(ctx, nil); return err },
		func() error {
			_, err := c.GuestRules(ctx, rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS, "172.16.0.14", nil, nil)
			return err
		},
	} {
		if err := call(); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("a call the helper lacks = %v, want ErrUnsupported", err)
		}
	}
	if got := h.seen(); len(got) != 0 {
		t.Fatalf("an older helper was sent %q", got)
	}
}
