package config

import (
	"strings"
	"testing"
)

func TestCoverage97LoadRejectsRateAndEnterpriseCluster(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "operator-pat")
	t.Setenv("SB_MCP_RATE_LIMIT", "-1")
	t.Setenv("SB_MCP_ALLOWED_ORIGINS", "https://app.example")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "SB_MCP_RATE_LIMIT") {
		t.Fatalf("rate limit err = %v", err)
	}
	if got := splitEnvList("SB_MCP_ALLOWED_ORIGINS"); len(got) != 1 || got[0] != "https://app.example" {
		t.Fatalf("origins = %#v", got)
	}

	// Insecure gossip is legal on a private cluster and illegal once
	// enterprise mode is on. Backup count 1 passes the cluster floor
	// (>= 1) and fails the enterprise floor (>= 2).
	base := map[string]string{
		"SB_PAT_TOKEN":                        strings.Repeat("x", minEnterpriseCredentialBytes),
		"SB_ENTERPRISE_MODE":                  "true",
		"SB_ENABLE_CLUSTER":                   "true",
		"SB_CLUSTER_BOOTSTRAP":                "true",
		"SB_CLUSTER_TLS_DIR":                  t.TempDir(),
		"SB_SECRET_AUDIT_EXPORT_URL":          "https://audit.example/export",
		"SB_SECRET_AUDIT_EXPORT_BEARER_TOKEN": strings.Repeat("e", minEnterpriseCredentialBytes),
		"SB_GOSSIP_SECRET_KEY":                strings.Repeat("g", 32),
		"SB_CREDENTIAL_ENCRYPTION_KEY":        strings.Repeat("k", 32),
		"SB_MCP_RATE_LIMIT":                   "20",
	}
	t.Run("insecure gossip", func(t *testing.T) {
		for k, v := range base {
			t.Setenv(k, v)
		}
		t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "true")
		t.Setenv("SB_SECRET_RECIPIENT_BACKUP_COUNT", "2")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "insecure escape hatches") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("one backup", func(t *testing.T) {
		for k, v := range base {
			t.Setenv(k, v)
		}
		t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "false")
		t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "false")
		t.Setenv("SB_SECRET_RECIPIENT_BACKUP_COUNT", "1")
		if _, err := Load(); err == nil || !strings.Contains(err.Error(), "at least two backups") {
			t.Fatalf("err = %v", err)
		}
	})
}
