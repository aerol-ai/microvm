package service

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestProbeSSHGatewaySucceedsWhenListenerAccepts(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	if err := probeSSHGateway(context.Background(), ln.Addr().String()); err != nil {
		t.Fatalf("probeSSHGateway: %v", err)
	}
}

func TestProbeSSHGatewayFailsWhenNothingListening(t *testing.T) {
	// Pick a port, close the listener, then probe — guaranteed connection refused.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	// Give the kernel a beat to mark the port as not listening.
	time.Sleep(50 * time.Millisecond)

	err = probeSSHGateway(context.Background(), addr)
	if err == nil {
		t.Fatal("expected probe to fail with no listener")
	}
	if !strings.Contains(err.Error(), "ssh gateway dial") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProbeSSHGatewayRejectsEmptyAddr(t *testing.T) {
	if err := probeSSHGateway(context.Background(), ""); err == nil {
		t.Fatal("expected error for empty addr")
	}
}

func TestProbeSSHGatewayRejectsInvalidAddr(t *testing.T) {
	if err := probeSSHGateway(context.Background(), "no-port"); err == nil {
		t.Fatal("expected error for invalid addr")
	}
}

// TestHealthSSHGatewayFollowsNodeRole: /health probes the SSH gateway on
// exactly the nodes that start it (config.Config.RunsSSHGateway). A
// server-only node of a role-split cluster, with SB_ENABLE_SSH_GATEWAY on and
// nothing listening, reports the gateway "disabled" and stays ok; it used to
// report "degraded" forever ("ssh gateway dial: ... connection refused"). A
// worker or the ingress still probes it: up is ok, down degrades.
func TestHealthSSHGatewayFollowsNodeRole(t *testing.T) {
	up, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer up.Close()
	go func() {
		for {
			conn, err := up.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()
	gone, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	down := gone.Addr().String()
	_ = gone.Close()

	cases := []struct {
		name       string
		role       string
		enabled    bool
		addr       string
		wantSSH    string // exact, or a prefix when it ends in "*"
		wantStatus string
	}{
		{"server-only, gateway enabled, nothing listening", config.NodeRoleServer, true, down, "disabled", "ok"},
		{"worker, gateway up", config.NodeRoleWorker, true, up.Addr().String(), "ok", "ok"},
		{"ingress, gateway up", config.NodeRoleIngress, true, up.Addr().String(), "ok", "ok"},
		{"worker, gateway down", config.NodeRoleWorker, true, down, "ssh gateway dial*", "degraded"},
		{"ingress, gateway down", config.NodeRoleIngress, true, down, "ssh gateway dial*", "degraded"},
		{"single node (no role), gateway up", "", true, up.Addr().String(), "ok", "ok"},
		{"gateway off", config.NodeRoleWorker, false, down, "disabled", "ok"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
			svc.docker = &fakeCapacityRuntime{}
			svc.cfg.NodeRole = tc.role
			svc.cfg.EnableSSHGateway = tc.enabled
			svc.cfg.SSHListenAddr = tc.addr
			health, err := svc.Health(context.Background())
			if err != nil {
				t.Fatalf("Health: %v", err)
			}
			if prefix, ok := strings.CutSuffix(tc.wantSSH, "*"); ok {
				if !strings.HasPrefix(health.SSHGateway, prefix) {
					t.Fatalf("ssh_gateway = %q, want it to start with %q", health.SSHGateway, prefix)
				}
			} else if health.SSHGateway != tc.wantSSH {
				t.Fatalf("ssh_gateway = %q, want %q", health.SSHGateway, tc.wantSSH)
			}
			if health.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q (health %+v)", health.Status, tc.wantStatus, health)
			}
		})
	}
}
