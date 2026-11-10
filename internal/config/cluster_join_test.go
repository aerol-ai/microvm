package config

import (
	"strings"
	"testing"
	"time"
)

// Join listener, CA store and node-cert TTL settings
// (plans/kubectl-style-cluster-ops.md eng D3, D5, §4.2).

func setJoinClusterEnv(t *testing.T, role string) {
	t.Helper()
	t.Setenv("SB_PAT_TOKEN", "token")
	t.Setenv("SB_ENABLE_CLUSTER", "true")
	t.Setenv("SB_NODE_ROLE", role)
	if role == NodeRoleWorker || role == NodeRoleIngress {
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "false")
		t.Setenv("SB_BOOTSTRAP_PEERS", "10.0.0.1:7001")
	} else {
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
	}
	t.Setenv("SB_GOSSIP_SECRET_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	t.Setenv("SB_CLUSTER_TLS_DIR", t.TempDir())
	t.Setenv("SB_CLUSTER_JOIN_LISTEN_ADDR", "")
	t.Setenv("SB_CLUSTER_CA_DIR", "")
	t.Setenv("SB_CLUSTER_NODE_CERT_TTL", "")
}

func TestClusterJoinListenAddr(t *testing.T) {
	cases := []struct {
		name, role, env, want string
	}{
		{"server default", NodeRoleServer, "", "0.0.0.0:7003"},
		{"mixed default", NodeRoleMixed, "", "0.0.0.0:7003"},
		{"server+worker default", "server,worker", "", "0.0.0.0:7003"},
		{"server custom", NodeRoleServer, "10.0.0.5:17003", "10.0.0.5:17003"},
		{"server off", NodeRoleServer, "off", ""},
		{"server disabled", NodeRoleServer, "Disabled", ""},
		{"server cleared", NodeRoleServer, envClearSentinel, ""},
		{"worker never listens", NodeRoleWorker, "0.0.0.0:7003", ""},
		{"ingress never listens", NodeRoleIngress, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setJoinClusterEnv(t, tc.role)
			t.Setenv("SB_CLUSTER_JOIN_LISTEN_ADDR", tc.env)
			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() = %v", err)
			}
			if cfg.ClusterJoinListenAddr != tc.want {
				t.Fatalf("ClusterJoinListenAddr = %q, want %q", cfg.ClusterJoinListenAddr, tc.want)
			}
			if cfg.ClusterCADir != "/etc/sandboxd/cluster-ca" || cfg.ClusterNodeCertTTL != 90*24*time.Hour {
				t.Fatalf("defaults: CA dir %q, cert TTL %s", cfg.ClusterCADir, cfg.ClusterNodeCertTTL)
			}
		})
	}
	// Single-node mode never opens the join port.
	t.Run("single node", func(t *testing.T) {
		t.Setenv("SB_PAT_TOKEN", "token")
		t.Setenv("SB_ENABLE_CLUSTER", "false")
		t.Setenv("SB_NODE_ROLE", "")
		t.Setenv("SB_CLUSTER_JOIN_LISTEN_ADDR", "0.0.0.0:7003")
		cfg, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.ClusterJoinListenAddr != "" {
			t.Fatalf("single node join addr = %q", cfg.ClusterJoinListenAddr)
		}
	})
}

func TestClusterNodeCertTTLBounds(t *testing.T) {
	for env, ok := range map[string]bool{"10m": true, "5m": true, "2160h": true, "4m": false, "2161h": false} {
		t.Run(env, func(t *testing.T) {
			setJoinClusterEnv(t, NodeRoleServer)
			t.Setenv("SB_CLUSTER_NODE_CERT_TTL", env)
			t.Setenv("SB_CLUSTER_CA_DIR", "/srv/ca")
			cfg, err := Load()
			if ok {
				if err != nil {
					t.Fatalf("Load() = %v", err)
				}
				if want, _ := time.ParseDuration(env); cfg.ClusterNodeCertTTL != want || cfg.ClusterCADir != "/srv/ca" {
					t.Fatalf("TTL %s dir %q", cfg.ClusterNodeCertTTL, cfg.ClusterCADir)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "SB_CLUSTER_NODE_CERT_TTL") {
				t.Fatalf("Load() = %v, want a TTL error", err)
			}
		})
	}
}
