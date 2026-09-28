package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCoverage95LiftExternalWitnessRequired(t *testing.T) {
	// Open-source Noop has no independently retained witness; the flag must
	// fail closed before the daemon claims tamper-evidence.
	_ = setBaseRunEnv(t)
	t.Setenv("SB_SECRET_AUDIT_EXTERNAL_WITNESS", "true")
	if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err == nil {
		t.Fatal("expected external-witness boot failure under Noop control plane")
	}
}

func TestCoverage95LiftOTELWarnAndNetworkRules(t *testing.T) {
	_ = setBaseRunEnv(t)
	// WithEndpointURL rejects a scheme-less / empty-host URL so Run logs the
	// exporter failure and continues — the warn branches are otherwise lazy.
	t.Setenv("SB_OTEL_TRACES_ENABLED", "true")
	t.Setenv("SB_OTEL_TRACES_ENDPOINT", "http://")
	t.Setenv("SB_OTEL_METRICS_ENABLED", "true")
	t.Setenv("SB_OTEL_METRICS_ENDPOINT", "http://")
	t.Setenv("SB_ENABLE_NETWORK_RULES", "true")
	t.Setenv("SB_NETRULES_BACKEND", "iptables")
	if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err != nil {
		t.Logf("Run err (ok): %v", err)
	}
}

func TestCoverage95LiftAuditSinkDirBlocked(t *testing.T) {
	// secrets.jsonl lives under <dbDir>/audit; a regular file there makes
	// MkdirAll fail so strict boot refuses to claim a working sink.
	paths := setBaseRunEnv(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(paths.dbPath), "audit"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_SECRET_AUDIT_STRICT_BOOT", "true")
	if err := runWithAutoCancel(t, 500*time.Millisecond, nil); err == nil {
		t.Fatal("expected secret audit sink boot failure")
	}
}

func TestCoverage95LiftBypassMarkerWriteFails(t *testing.T) {
	paths := setBaseRunEnv(t)
	// writeBypassMarker writes path+".tmp" then renames; a tmp directory
	// makes the write fail without breaking store.Open.
	if err := os.Mkdir(filepath.Join(filepath.Dir(paths.dbPath), "bypass_last_enabled.tmp"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err != nil {
		t.Logf("Run err (ok): %v", err)
	}
}
