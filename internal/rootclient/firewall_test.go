package rootclient

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/aerol-ai/microvm/internal/rootd"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/rootpolicy"
)

// partsHelper serves PrepareSandbox and ReleaseSandbox with the parts it
// lists, and counts the calls that reach it.
type partsHelper struct {
	rootdpb.UnimplementedRootHelperServer
	parts    []string
	prepares atomic.Int32
	releases atomic.Int32
}

func (h *partsHelper) Version(context.Context, *rootdpb.VersionRequest) (*rootdpb.VersionResponse, error) {
	return &rootdpb.VersionResponse{HelperVersion: "n-1", Api: rootdpb.APIVersion, Features: rootdpb.Features(), Parts: h.parts}, nil
}

func (h *partsHelper) PrepareSandbox(context.Context, *rootdpb.PrepareSandboxRequest) (*rootdpb.PrepareSandboxResponse, error) {
	h.prepares.Add(1)
	return &rootdpb.PrepareSandboxResponse{NetnsPath: "/run/aerolvm-rootd/netns/sb-1", ContainerIp: "10.88.0.2"}, nil
}

func (h *partsHelper) ReleaseSandbox(context.Context, *rootdpb.ReleaseSandboxRequest) (*rootdpb.ReleaseSandboxResponse, error) {
	h.releases.Add(1)
	return &rootdpb.ReleaseSandboxResponse{}, nil
}

// TestPartsTheHelperLacks (eng review D5, M1 PR 5): an agent newer than its
// helper sends a part only when the handshake listed it. A create that
// needs a part the helper lacks fails before anything is sent, as an
// UnsupportedError (503, the swap brings the newer helper), never with
// the part dropped. The other direction, a helper refusing a part or a
// field it does not know, is rootd's TestPrepareSandboxRequests.
func TestPartsTheHelperLacks(t *testing.T) {
	sock := newOwnedSocket(t)
	h := &partsHelper{parts: []string{rootdpb.PartNetns}}
	sock.serve(t, h)
	c := New(Config{Socket: sock.path, HelperUID: uint32(os.Getuid())})
	t.Cleanup(func() { _ = c.Close() })
	ctx := ctxT(t)
	if parts, err := c.Parts(ctx); err != nil || !slices.Equal(parts, []string{rootdpb.PartNetns}) {
		t.Fatalf("Parts = %v, %v", parts, err)
	}
	both := []string{rootdpb.PartNetns, rootdpb.PartFirewall}
	_, err := c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: both})
	var ue *UnsupportedError
	if !errors.As(err, &ue) || !errors.Is(err, ErrUnsupported) || h.prepares.Load() != 0 {
		t.Fatalf("a part the helper lacks = %v (sent %d)", err, h.prepares.Load())
	}
	if err := c.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-1", ContainerIp: "10.88.0.2", Parts: both}); !errors.Is(err, ErrUnsupported) || h.releases.Load() != 0 {
		t.Fatalf("a release with a part the helper lacks = %v (sent %d)", err, h.releases.Load())
	}
	// What it lists goes through.
	resp, err := c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: "sb-1", Parts: []string{rootdpb.PartNetns}})
	if err != nil || resp.GetContainerIp() != "10.88.0.2" || h.prepares.Load() != 1 {
		t.Fatalf("a listed part = %v, %v", resp, err)
	}
	if err := c.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: "sb-1", Parts: []string{rootdpb.PartNetns}}); err != nil || h.releases.Load() != 1 {
		t.Fatalf("release = %v", err)
	}
}

// memFirewall is rootd.FirewallHost in memory.
type memFirewall struct {
	calls []string
}

func (m *memFirewall) EnsureHost(context.Context) (error, error) {
	m.calls = append(m.calls, "ensure")
	return nil, nil
}
func (m *memFirewall) Reassert(context.Context) {}
func (m *memFirewall) SetNodeGuard(allow []rootpolicy.NodePort) (bool, error) {
	m.calls = append(m.calls, fmt.Sprintf("guard %v", allow))
	return true, nil
}
func (m *memFirewall) SetFloor(cidrs []netip.Prefix) (bool, error) {
	m.calls = append(m.calls, fmt.Sprintf("floor %v", cidrs))
	return false, nil
}
func (m *memFirewall) Rules(op rootdpb.SandboxRulesOp, ip string, allow, deny []string) (bool, error) {
	m.calls = append(m.calls, fmt.Sprintf("%v %s %v %v", op, ip, allow, deny))
	return true, nil
}
func (m *memFirewall) ClearAddress(ip string) error {
	m.calls = append(m.calls, "clear "+ip)
	return nil
}

// TestFirewallCallsWithTheRealHelper: the client's firewall calls reach
// the helper's server and come back with its answers.
func TestFirewallCallsWithTheRealHelper(t *testing.T) {
	sock := sockPath(t)
	mn, fw := newMemNet(), &memFirewall{}
	realHelper(t, sock, func(o *rootd.Options) { o.Network, o.Firewall = mn, fw })
	c := newClient(t, sock)
	ctx := ctxT(t)
	if fence, err := c.EnsureHostFirewall(ctx); err != nil || fence != "" {
		t.Fatalf("EnsureHostFirewall = %q, %v", fence, err)
	}
	if err := c.EnsureHost(ctx); err != nil {
		t.Fatal(err)
	}
	if rep, err := c.SetNodeGuard(ctx, []*rootdpb.NodePort{{Proto: "tcp", Port: 15080}}); err != nil || !rep {
		t.Fatalf("SetNodeGuard = %v, %v", rep, err)
	}
	if _, err := c.SetEgressFloor(ctx, []string{"10.20.0.0/16"}); err != nil {
		t.Fatal(err)
	}
	resp, err := c.PrepareSandbox(ctx, &rootdpb.PrepareSandboxRequest{NetnsName: "aerol-netns-0",
		Parts: []string{rootdpb.PartNetns, rootdpb.PartFirewall}, Firewall: &rootdpb.SandboxFirewall{BlockAllEgress: true}})
	if err != nil || resp.GetContainerIp() == "" {
		t.Fatalf("PrepareSandbox = %v, %v", resp, err)
	}
	ip := resp.GetContainerIp()
	if ins, err := c.SandboxRules(ctx, rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_HOLD_EGRESS, ip, nil, nil); err != nil || !ins {
		t.Fatalf("SandboxRules = %v, %v", ins, err)
	}
	if err := c.ReleaseSandbox(ctx, &rootdpb.ReleaseSandboxRequest{NetnsName: "aerol-netns-0", ContainerIp: ip,
		Parts: []string{rootdpb.PartNetns, rootdpb.PartFirewall}}); err != nil {
		t.Fatal(err)
	}
	if n := len(fw.calls); n != 7 || fw.calls[n-1] != "clear "+ip {
		t.Fatalf("calls %q", fw.calls)
	}
	// A refused address is a refusal.
	if _, err := c.SandboxRules(ctx, rootdpb.SandboxRulesOp_SANDBOX_RULES_OP_BLOCK_EGRESS, "8.8.8.8", nil, nil); !errors.Is(err, ErrRefused) {
		t.Fatalf("an outside address = %v", err)
	}
}
