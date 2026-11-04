package config

import (
	"slices"
	"strings"
	"testing"
)

func TestParseSandboxNodePorts(t *testing.T) {
	cases := []struct {
		raw  string
		want []SandboxNodePort
		err  bool
	}{
		{raw: "", want: nil},
		{raw: " , ", want: nil},
		{raw: "8080", want: []SandboxNodePort{{"tcp", 8080}}},
		{raw: "8080, 5353/udp,9000/TCP,8080", want: []SandboxNodePort{{"tcp", 8080}, {"udp", 5353}, {"tcp", 9000}}},
		{raw: "0", err: true},
		{raw: "65536", err: true},
		{raw: "8000-9000", err: true},
		{raw: "all", err: true},
		{raw: "53/sctp", err: true},
	}
	for _, tc := range cases {
		got, err := ParseSandboxNodePorts(tc.raw)
		if (err != nil) != tc.err {
			t.Fatalf("%q: err = %v, want error %v", tc.raw, err, tc.err)
		}
		if !tc.err && !slices.Equal(got, tc.want) {
			t.Fatalf("%q = %v, want %v", tc.raw, got, tc.want)
		}
	}
	if (SandboxNodePort{"udp", 53}).String() != "53/udp" {
		t.Fatal("String")
	}
}

func TestNodeControlPorts(t *testing.T) {
	c := Config{APIPort: 21212, SSHListenAddr: "0.0.0.0:2220", RaftBindAddr: "0.0.0.0:7000", GossipBindAddr: "0.0.0.0:7001",
		ClusterInternalListenAddr: "bad", HostPortRedirectPort: 21215}
	if got, want := c.NodeControlPorts(), []uint16{22, 111, 21212, 2220, 7000, 7001}; !slices.Equal(got, want) {
		t.Fatalf("control ports = %v, want %v", got, want)
	}
	c.IngressProxyRouting = true
	if !slices.Contains(c.NodeControlPorts(), 21215) {
		t.Fatal("with ingress proxy routing the redirect listener is a control port")
	}
}

// TestSandboxNodePortsLoad: the escape hatch loads, refuses control ports
// and the gateway's own ports, and is refused outright in enterprise mode.
func TestSandboxNodePortsLoad(t *testing.T) {
	t.Setenv("SB_ENABLE_CLUSTER", "false")
	t.Setenv("SB_PAT_TOKEN", "test-token")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SandboxNodePortsAllow) != 0 || cfg.EgressDNSPort != 53054 || cfg.EgressProxyPort != 15080 {
		t.Fatalf("defaults: %v %d %d", cfg.SandboxNodePortsAllow, cfg.EgressDNSPort, cfg.EgressProxyPort)
	}
	t.Setenv("SB_SANDBOX_NODE_PORTS_ALLOW", "8080,5353/udp")
	if cfg, err = Load(); err != nil || !slices.Equal(cfg.SandboxNodePortsAllow, []SandboxNodePort{{"tcp", 8080}, {"udp", 5353}}) {
		t.Fatalf("allow list: %v %v", cfg.SandboxNodePortsAllow, err)
	}
	for raw, want := range map[string]string{
		"nope":   "invalid SB_SANDBOX_NODE_PORTS_ALLOW",
		"22":     "control or host-service",
		"21212":  "control or host-service",
		"7001":   "control or host-service",
		"15080":  "egress gateway's own port",
		"53054":  "egress gateway's own port",
		"2220/u": "invalid",
	} {
		t.Setenv("SB_SANDBOX_NODE_PORTS_ALLOW", raw)
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want %q", raw, err, want)
		}
	}
	t.Setenv("SB_SANDBOX_NODE_PORTS_ALLOW", "")
	for env, want := range map[string]string{"SB_EGRESS_DNS_PORT": "invalid SB_EGRESS_DNS_PORT", "SB_EGRESS_PROXY_PORT": "invalid SB_EGRESS_PROXY_PORT"} {
		t.Setenv(env, "0")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s=0: %v", env, err)
		}
		t.Setenv(env, "")
	}
	t.Setenv("SB_EGRESS_PROXY_PORT", "53054")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "must differ") {
		t.Errorf("equal gateway ports: %v", err)
	}
	t.Setenv("SB_EGRESS_PROXY_PORT", "")

	// Enterprise mode: any entry refuses the boot.
	t.Setenv("SB_PAT_TOKEN", strings.Repeat("x", minEnterpriseCredentialBytes))
	t.Setenv("SB_ENTERPRISE_MODE", "true")
	t.Setenv("SB_SECRET_AUDIT_EXTERNAL_WITNESS", "true")
	t.Setenv("SB_SECRET_AUDIT_EXPORT_URL", "https://audit.example/export")
	t.Setenv("SB_SECRET_AUDIT_EXPORT_BEARER_TOKEN", strings.Repeat("e", minEnterpriseCredentialBytes))
	if _, err := Load(); err != nil {
		t.Fatalf("enterprise without the hatch: %v", err)
	}
	t.Setenv("SB_SANDBOX_NODE_PORTS_ALLOW", "8080")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SB_SANDBOX_NODE_PORTS_ALLOW must be empty when SB_ENTERPRISE_MODE=true") {
		t.Fatalf("enterprise with the hatch: %v", err)
	}
}
