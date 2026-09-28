package daemon

import (
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
)

func TestOnDemandTLSOnThisNode(t *testing.T) {
	tests := []struct {
		name string
		cfg  config.Config
		want bool
	}{
		{"flag off, ingress-only: unchanged", config.Config{NodeRole: config.NodeRoleIngress}, true},
		{"flag on, ingress-only: skip (owners terminate)", config.Config{IngressProxyRouting: true, NodeRole: config.NodeRoleIngress}, false},
		{"flag on, worker: install", config.Config{IngressProxyRouting: true, NodeRole: config.NodeRoleWorker}, true},
		{"flag on, ingress+worker: install (it owns sandboxes)", config.Config{IngressProxyRouting: true, NodeRole: config.NodeRoleIngress + "," + config.NodeRoleWorker}, true},
		{"flag on, legacy empty role: install (all roles)", config.Config{IngressProxyRouting: true}, true},
		{"flag on, mixed: install", config.Config{IngressProxyRouting: true, NodeRole: config.NodeRoleMixed}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := onDemandTLSOnThisNode(tc.cfg); got != tc.want {
				t.Fatalf("onDemandTLSOnThisNode(%q) = %v, want %v (roles %v)", tc.cfg.NodeRole, got, tc.want, tc.cfg.Roles())
			}
		})
	}
}
