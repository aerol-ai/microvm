package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/egresspolicy"
)

// TestConfigureHostMediatedNodeGuard: isolate (in this process) and the
// WASM workers (through their environment) get the same node ports: ingress
// on an ingress node and the operator's escape hatch, which is logged.
func TestConfigureHostMediatedNodeGuard(t *testing.T) {
	prev := egresspolicy.NodeAllowedPorts()
	t.Cleanup(func() { egresspolicy.SetNodeAllowedPorts(prev) })
	t.Setenv(egresspolicy.NodePortsEnv, "")
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	cfg := config.Config{NodeRole: config.NodeRoleMixed, EnableCaddy: true,
		SandboxNodePortsAllow: []config.SandboxNodePort{{Proto: "tcp", Port: 8443}}}
	configureHostMediatedNodeGuard(cfg, logger)
	if got := egresspolicy.NodeAllowedPorts(); !slices.Equal(got, []uint16{80, 443, 8443}) {
		t.Fatalf("in-process ports = %v", got)
	}
	if got := os.Getenv(egresspolicy.NodePortsEnv); got != "80,443,8443" {
		t.Fatalf("worker env = %q", got)
	}
	if !strings.Contains(logs.String(), "SB_SANDBOX_NODE_PORTS_ALLOW") {
		t.Fatalf("the escape hatch must be logged: %s", logs.String())
	}
	logs.Reset()
	configureHostMediatedNodeGuard(config.Config{NodeRole: config.NodeRoleWorker}, logger)
	if got := egresspolicy.NodeAllowedPorts(); len(got) != 0 || os.Getenv(egresspolicy.NodePortsEnv) != "" || logs.Len() != 0 {
		t.Fatalf("a worker with no hatch allows nothing: %v %q %s", got, os.Getenv(egresspolicy.NodePortsEnv), logs.String())
	}
}

// TestConfigureEgressRanges (C24): isolate and the host-firewall floor (in
// this process) and the WASM workers (through their environment, which a
// worker reads back) get the same deny floor and private ranges.
func TestConfigureEgressRanges(t *testing.T) {
	prevFloor, prevPrivate := egresspolicy.ExtraDenyFloor(), egresspolicy.ExtraPrivateRanges()
	t.Cleanup(func() { egresspolicy.SetRanges(prevFloor, prevPrivate) })
	t.Setenv(egresspolicy.DenyFloorEnv, "")
	t.Setenv(egresspolicy.PrivateRangesEnv, "")
	t.Setenv(egresspolicy.BlockPrivateEnv, "")
	t.Setenv(egresspolicy.FloorFileEnv, "")
	prevFile := egresspolicy.FileFloor()
	t.Cleanup(func() { egresspolicy.SetFileFloor(prevFile) })
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))
	floor := []netip.Prefix{netip.MustParsePrefix("10.96.0.1/32")}
	private := []netip.Prefix{netip.MustParsePrefix("10.244.0.0/16"), netip.MustParsePrefix("198.18.0.0/15")}
	configureEgressRanges(config.Config{EgressDenyFloorCIDRs: floor, EgressPrivateDefaultCIDRs: private, EgressBlockPrivateByDefault: true}, logger)
	if !slices.Equal(egresspolicy.ExtraDenyFloor(), floor) || !slices.Equal(egresspolicy.ExtraPrivateRanges(), private) {
		t.Fatalf("in-process lists = %v %v", egresspolicy.ExtraDenyFloor(), egresspolicy.ExtraPrivateRanges())
	}
	if os.Getenv(egresspolicy.DenyFloorEnv) != "10.96.0.1/32" || os.Getenv(egresspolicy.PrivateRangesEnv) != "10.244.0.0/16,198.18.0.0/15" || os.Getenv(egresspolicy.BlockPrivateEnv) != "true" {
		t.Fatalf("worker env = %q %q %q", os.Getenv(egresspolicy.DenyFloorEnv), os.Getenv(egresspolicy.PrivateRangesEnv), os.Getenv(egresspolicy.BlockPrivateEnv))
	}
	// What a worker does at start reads back the same lists.
	egresspolicy.SetRanges(nil, nil)
	if err := egresspolicy.LoadRangesFromEnv(); err != nil || !slices.Equal(egresspolicy.ExtraDenyFloor(), floor) || !slices.Equal(egresspolicy.ExtraPrivateRanges(), private) {
		t.Fatalf("a worker reads %v %v (%v)", egresspolicy.ExtraDenyFloor(), egresspolicy.ExtraPrivateRanges(), err)
	}
	if !strings.Contains(logs.String(), "deny_floor=10.96.0.1/32") {
		t.Fatalf("the lists must be logged: %s", logs.String())
	}
	// The floor file: its addresses join the floor here, and a worker gets
	// its path to watch.
	moved := netip.MustParsePrefix("172.18.0.44/32")
	configureEgressRanges(config.Config{EgressDenyFloorCIDRs: floor, EgressDenyFloorFile: "/etc/aerolvm-egress-floor/deny-floor",
		EgressDenyFloorFileCIDRs: []netip.Prefix{moved}}, logger)
	if !slices.Contains(egresspolicy.ExtraDenyFloor(), moved) || os.Getenv(egresspolicy.FloorFileEnv) != "/etc/aerolvm-egress-floor/deny-floor" {
		t.Fatalf("floor file: %v %q", egresspolicy.ExtraDenyFloor(), os.Getenv(egresspolicy.FloorFileEnv))
	}
	if !strings.Contains(logs.String(), "deny-floor file") {
		t.Fatalf("the floor file must be logged: %s", logs.String())
	}
	logs.Reset()
	configureEgressRanges(config.Config{}, logger)
	if len(egresspolicy.ExtraDenyFloor()) != 0 || os.Getenv(egresspolicy.DenyFloorEnv) != "" || os.Getenv(egresspolicy.BlockPrivateEnv) != "false" || logs.Len() != 0 {
		t.Fatalf("no lists, nothing: %v %q %s", egresspolicy.ExtraDenyFloor(), os.Getenv(egresspolicy.DenyFloorEnv), logs.String())
	}
}

// TestWireNodeGuard: only nodes that own sandboxes run it; a worker starts
// the node guard's and the egress floor's supervisors, which stop with the
// context.
func TestWireNodeGuard(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wireNodeGuard(ctx, config.Config{NodeRole: config.NodeRoleServer}, nil)
	svc := service.New(config.Config{NodeRole: config.NodeRoleWorker}, testLogger(), nil, nil, nil, nil, nil, nil, nil)
	wireNodeGuard(ctx, config.Config{NodeRole: config.NodeRoleWorker}, svc)
}
