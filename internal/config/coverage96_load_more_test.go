package config

import (
	"strings"
	"testing"
)

func TestCov96LoadRejectsSecretProviderAndAuditBounds(t *testing.T) {
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "unknown provider", env: map[string]string{"SB_SECRET_PROVIDER": "gcpkms"}, want: "SB_SECRET_PROVIDER must be local, awskms, or vault"},
		{name: "vault provider", env: map[string]string{"SB_SECRET_PROVIDER": "vault"}, want: "vault is not implemented"},
		{name: "awskms without key", env: map[string]string{"SB_SECRET_PROVIDER": "awskms"}, want: "SB_SECRET_AWS_KMS_KEY_ID"},
		{name: "negative audit retention", env: map[string]string{"SB_SECRET_AUDIT_RETENTION_DAYS": "-1"}, want: "SB_SECRET_AUDIT_RETENTION_DAYS"},
		{name: "deleted grace over a day", env: map[string]string{"SB_AUDIT_DELETED_GRACE": "25h"}, want: "SB_AUDIT_DELETED_GRACE must be <= 24h"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestCov96LoadEnterpriseRejectsHardeningOptOuts(t *testing.T) {
	enterprise := map[string]string{
		"SB_PAT_TOKEN":                        strings.Repeat("x", minEnterpriseCredentialBytes),
		"SB_ENTERPRISE_MODE":                  "true",
		"SB_ENABLE_CLUSTER":                   "false",
		"SB_SECRET_AUDIT_EXPORT_URL":          "https://audit.example/export",
		"SB_SECRET_AUDIT_EXPORT_BEARER_TOKEN": strings.Repeat("e", minEnterpriseCredentialBytes),
	}
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "privileged containers", env: map[string]string{"SB_CONTAINER_PRIVILEGED": "true"}, want: "SB_CONTAINER_PRIVILEGED must be false"},
		{name: "resource limits off", env: map[string]string{"SB_RESOURCE_LIMITS_DISABLED": "true"}, want: "SB_RESOURCE_LIMITS_DISABLED must be false"},
		{name: "lenient audit boot", env: map[string]string{"SB_SECRET_AUDIT_STRICT_BOOT": "false"}, want: "SB_SECRET_AUDIT_STRICT_BOOT must be true"},
		{name: "lenient awskms boot", env: map[string]string{
			"SB_SECRET_PROVIDER":             "awskms",
			"SB_SECRET_AWS_KMS_KEY_ID":       "alias/aerolvm",
			"SB_SECRET_PROVIDER_STRICT_BOOT": "false",
		}, want: "SB_SECRET_PROVIDER_STRICT_BOOT must be true for awskms"},
		{name: "zero tomb retention", env: map[string]string{"SB_SECRET_TOMB_RETENTION_DAYS": "0"}, want: "retention must be non-zero"},
		{name: "unbounded egress evidence", env: map[string]string{"SB_AUDIT_EGRESS_SANDBOX_RATE": "0"}, want: "SB_AUDIT_EGRESS_SANDBOX_RATE must be > 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for k, v := range mergeEnv(enterprise, tc.env) {
				t.Setenv(k, v)
			}
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}
