package config

import (
	"strings"
	"testing"
)

func TestAgentSandboxAPIConfig(t *testing.T) {
	for _, tc := range []struct {
		name, value string
		want        map[string]string
		wantErr     string
	}{
		{name: "none"},
		{name: "pairs", value: " acct = acct:k1 ,ops=team:platform", want: map[string]string{"acct": "acct:k1", "ops": "team:platform"}},
		{name: "no owner", value: "acct=", wantErr: "is not"},
		{name: "no pair", value: "acct", wantErr: "is not"},
		{name: "bad namespace", value: "Acct=acct:k1", wantErr: "is not"},
		{name: "a namespace twice", value: "a=x,a=y", wantErr: "twice"},
		{name: "an owner twice", value: "a=x,b=x", wantErr: "twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_AGENT_SANDBOX_API_NAMESPACES", tc.value)
			t.Setenv("SB_ENTERPRISE_MODE", "false")
			t.Setenv("SB_PAT_TOKEN", "pat-token")
			cfg, err := Load()
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("Load = %v, want %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.AgentSandboxAPINamespaces) != len(tc.want) {
				t.Fatalf("namespaces = %v", cfg.AgentSandboxAPINamespaces)
			}
			for k, v := range tc.want {
				if cfg.AgentSandboxAPINamespaces[k] != v {
					t.Fatalf("namespaces = %v", cfg.AgentSandboxAPINamespaces)
				}
			}
			if cfg.AgentSandboxAPIAddr != ":9443" || !strings.HasSuffix(cfg.AgentSandboxAPICertFile, "tls.crt") {
				t.Fatalf("defaults = %q %q", cfg.AgentSandboxAPIAddr, cfg.AgentSandboxAPICertFile)
			}
		})
	}
}
