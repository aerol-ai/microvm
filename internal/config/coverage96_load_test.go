package config

import (
	"strings"
	"testing"
)

func TestCov96LoadRejectsRemainingBounds(t *testing.T) {
	jail := map[string]string{
		"SB_PAT_TOKEN":                "operator-pat",
		"SB_ENABLE_ISOLATE":           "true",
		"SB_ISOLATE_WORKERD_PATH":     "/usr/bin/workerd",
		"SB_ISOLATE_RUN_DIR":          "/var/run/isolate",
		"SB_ISOLATE_USE_JAIL":         "true",
		"SB_ISOLATE_JAIL_CHROOT_BASE": "/var/lib/isolate",
		"SB_ISOLATE_JAIL_UID":         "65534",
		"SB_ISOLATE_JAIL_GID":         "65534",
		"SB_ISOLATE_JAIL_CGROUP_ROOT": "/sys/fs/cgroup",
	}
	cases := []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "jail pids", env: mergeEnv(jail, map[string]string{"SB_ISOLATE_JAIL_PIDS_MAX": "-1"}), want: "SB_ISOLATE_JAIL_PIDS_MAX"},
		{name: "boot verify", env: map[string]string{"SB_SECRET_AUDIT_BOOT_VERIFY": "nope"}, want: "SB_SECRET_AUDIT_BOOT_VERIFY"},
		{name: "tomb days", env: map[string]string{"SB_SECRET_TOMB_RETENTION_DAYS": "-1"}, want: "SB_SECRET_TOMB_RETENTION_DAYS"},
		{name: "outbox grace", env: map[string]string{"SB_SECRET_OUTBOX_STANDALONE_GRACE": "-1s"}, want: "SB_SECRET_OUTBOX_STANDALONE_GRACE"},
		{name: "rate identity", env: map[string]string{"SB_AUDIT_RATE_LIMIT_IDENTITY": "0"}, want: "SB_AUDIT_RATE_LIMIT_IDENTITY"},
		{name: "rate operator", env: map[string]string{"SB_AUDIT_RATE_LIMIT_OPERATOR": "0"}, want: "SB_AUDIT_RATE_LIMIT_OPERATOR"},
		{name: "rate node", env: map[string]string{"SB_AUDIT_RATE_LIMIT_NODE": "0"}, want: "SB_AUDIT_RATE_LIMIT_NODE"},
		{name: "egress burst", env: map[string]string{"SB_AUDIT_EGRESS_SANDBOX_BURST": "0"}, want: "SB_AUDIT_EGRESS_SANDBOX_BURST"},
		{name: "egress rate", env: map[string]string{"SB_AUDIT_EGRESS_SANDBOX_RATE": "-1"}, want: "SB_AUDIT_EGRESS_SANDBOX_RATE"},
		{name: "queue max", env: map[string]string{"SB_AUDIT_QUEUE_MAX": "-1"}, want: "SB_AUDIT_QUEUE_MAX"},
		{name: "overflow", env: map[string]string{"SB_AUDIT_OVERFLOW_POLICY": "drop"}, want: "SB_AUDIT_OVERFLOW_POLICY"},
		{name: "deleted grace", env: map[string]string{"SB_AUDIT_DELETED_GRACE": "-1s"}, want: "SB_AUDIT_DELETED_GRACE"},
		{name: "deleted index", env: map[string]string{"SB_AUDIT_DELETED_INDEX_MAX": "-1"}, want: "SB_AUDIT_DELETED_INDEX_MAX"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SB_PAT_TOKEN", "operator-pat")
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %s", err, tc.want)
			}
		})
	}
}

func TestCov96LoadAppliesWebhookAliases(t *testing.T) {
	t.Setenv("SB_PAT_TOKEN", "operator-pat")
	t.Setenv("SB_AUDIT_EXPORT_WEBHOOK_URL", "https://audit.example/hook")
	t.Setenv("SB_AUDIT_EXPORT_WEBHOOK_BEARER_TOKEN", "bearer-token")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SecretAuditExportURL != "https://audit.example/hook" || cfg.SecretAuditExportBearerToken != "bearer-token" {
		t.Fatalf("aliases url=%q token=%q", cfg.SecretAuditExportURL, cfg.SecretAuditExportBearerToken)
	}
}

func mergeEnv(base, extra map[string]string) map[string]string {
	out := make(map[string]string, len(base)+len(extra))
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}
