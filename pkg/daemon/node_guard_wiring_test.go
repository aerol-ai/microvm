package daemon

import (
	"bytes"
	"context"
	"log/slog"
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
