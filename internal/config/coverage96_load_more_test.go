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
		{name: "unknown provider", env: map[string]string{"SB_SECRET_PROVIDER": "gcpkms"}, want: "SB_SECRET_PROVIDER must be local, awskms, vault, or pkcs11"},
		{name: "vault without an address", env: map[string]string{"SB_SECRET_PROVIDER": "vault", "SB_SECRET_VAULT_KEY_NAME": "aerolvm"}, want: "SB_SECRET_VAULT_ADDR is required"},
		{name: "vault without a key", env: map[string]string{"SB_SECRET_PROVIDER": "vault", "SB_SECRET_VAULT_ADDR": "https://vault.example"}, want: "SB_SECRET_VAULT_KEY_NAME"},
		{name: "vault over plain http", env: map[string]string{"SB_SECRET_PROVIDER": "vault", "SB_SECRET_VAULT_ADDR": "http://vault.example:8200", "SB_SECRET_VAULT_KEY_NAME": "aerolvm"}, want: "non-loopback"},
		{name: "partial vault settings beside awskms", env: map[string]string{"SB_SECRET_PROVIDER": "awskms", "SB_SECRET_AWS_KMS_KEY_ID": "alias/aerolvm", "SB_SECRET_VAULT_KEY_NAME": "aerolvm"}, want: "SB_SECRET_VAULT_ADDR is required"},
		{name: "pkcs11 without a module", env: map[string]string{"SB_SECRET_PROVIDER": "pkcs11"}, want: "SB_SECRET_PKCS11_MODULE is required"},
		{name: "pkcs11 without a token label", env: map[string]string{"SB_SECRET_PROVIDER": "pkcs11", "SB_SECRET_PKCS11_MODULE": "/m.so"}, want: "SB_SECRET_PKCS11_TOKEN_LABEL is required"},
		{name: "pkcs11 bad IV mode", env: map[string]string{"SB_SECRET_PROVIDER": "pkcs11", "SB_SECRET_PKCS11_MODULE": "/m.so", "SB_SECRET_PKCS11_TOKEN_LABEL": "t", "SB_SECRET_PKCS11_PIN_FILE": "/p", "SB_SECRET_PKCS11_KEY_LABEL": "k", "SB_SECRET_PKCS11_GCM_IV": "random"}, want: "SB_SECRET_PKCS11_GCM_IV must be"},
		{name: "pkcs11 settings beside awskms, pin missing", env: map[string]string{"SB_SECRET_PROVIDER": "awskms", "SB_SECRET_AWS_KMS_KEY_ID": "alias/x", "SB_SECRET_PKCS11_MODULE": "/m.so", "SB_SECRET_PKCS11_TOKEN_LABEL": "t", "SB_SECRET_PKCS11_PIN_FILE": "/nonexistent/pin", "SB_SECRET_PKCS11_KEY_LABEL": "k"}, want: "SB_SECRET_PKCS11_PIN_FILE"},
		{name: "zero in-flight cap", env: map[string]string{"SB_SECRET_PROVIDER_MAX_INFLIGHT": "0"}, want: "SB_SECRET_PROVIDER_MAX_INFLIGHT must be between 1 and 256"},
		{name: "in-flight cap over 256", env: map[string]string{"SB_SECRET_PROVIDER_MAX_INFLIGHT": "257"}, want: "SB_SECRET_PROVIDER_MAX_INFLIGHT must be between 1 and 256"},
		{name: "unknown key custody", env: map[string]string{"SB_CREDENTIAL_KEY_CUSTODY": "hsm"}, want: "SB_CREDENTIAL_KEY_CUSTODY must be file or wrapped"},
		{name: "wrapped custody with local provider", env: map[string]string{"SB_CREDENTIAL_KEY_CUSTODY": "wrapped"}, want: "needs an external SB_SECRET_PROVIDER"},
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
