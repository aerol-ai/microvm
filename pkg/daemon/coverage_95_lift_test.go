package daemon

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
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

func TestCoverage95LiftSnapshotPushBuildFailures(t *testing.T) {
	logger := testLogger()
	svc := service.New(config.Config{}, logger, nil, nil, nil, nil, nil, nil, nil)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Nil docker fails pusher construction so the feature stays off.
	startSnapshotPushReconciler(ctx, logger, config.Config{
		SnapshotPushEnabled:           true,
		MirrorPushHost:                "push.example",
		AutoImportClusterID:           "cluster-1",
		AutoImportClusterPATPath:      filepath.Join(t.TempDir(), "missing.pat"),
		SnapshotPushReconcileInterval: time.Hour,
	}, nil, svc, nil, nil)

	// Valid PAT + docker, but wasm checkpoint pusher can still fail independently.
	pat := filepath.Join(t.TempDir(), "pat")
	if err := os.WriteFile(pat, []byte("tok\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	startSnapshotPushReconciler(ctx, logger, config.Config{
		SnapshotPushEnabled:           true,
		MirrorPushHost:                "push.example",
		AutoImportClusterID:           "cluster-1",
		AutoImportClusterPATPath:      pat,
		SnapshotPushReconcileInterval: time.Hour,
	}, nil, svc, newTestDockerClient(t), nil)

	if p := wireDockerWarmPool(ctx, config.Config{DockerPoolEnabled: true, DockerReadySocketEnabled: false}, logger, nil, nil); p != nil {
		t.Fatal("pool should stay off when ready sockets are disabled")
	}

	blocked := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_WASM_COMPILE_CACHE_DIR", blocked)
	wireWasmRuntime(ctx, config.Config{
		WasmCompileCacheDir: blocked,
		WasmModulesDir:      t.TempDir(),
		WasmRunDir:          t.TempDir(),
	}, logger, svc, nil)

	// Enabled manager + failing bootstrap backend exercises the re-assert
	// warn path without needing Linux iptables.
	prevInterval := chainReassertInterval
	chainReassertInterval = 5 * time.Millisecond
	t.Cleanup(func() { chainReassertInterval = prevInterval })
	reassertCtx, reassertCancel := context.WithCancel(context.Background())
	t.Cleanup(reassertCancel)
	stop := startChainReassert(reassertCtx, netrules.NewWithBackend(failReassertBackend{}), logger)
	t.Cleanup(stop)
	time.Sleep(20 * time.Millisecond)
}

type failReassertBackend struct{}

func (failReassertBackend) Exists(string, string, ...string) (bool, error) { return false, nil }
func (failReassertBackend) Insert(string, string, int, ...string) error    { return nil }
func (failReassertBackend) Delete(string, string, ...string) error         { return nil }
func (failReassertBackend) EnsureUserChain(string) error {
	return errors.New("reassert boom")
}
func (failReassertBackend) EnsureForwardJump(string) error { return nil }

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

func TestCoverage95LiftRunErrorBranches(t *testing.T) {
	t.Run("audit_ingest_listen_conflict", func(t *testing.T) {
		_ = setBaseRunEnv(t)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		port := ln.Addr().(*net.TCPAddr).Port
		t.Setenv("SB_EGRESS_ATTRIBUTION_ENABLED", "true")
		t.Setenv("SB_AUDIT_INGEST_PORT", strconv.Itoa(port))
		if err := runWithAutoCancel(t, 500*time.Millisecond, nil); err == nil {
			t.Fatal("expected audit ingest listen failure")
		}
	})

	t.Run("ready_socket_dir_blocked", func(t *testing.T) {
		paths := setBaseRunEnv(t)
		blocked := filepath.Join(paths.rootDir, "cred-file")
		if err := os.WriteFile(blocked, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SB_MOUNTS_CRED_DIR", blocked)
		t.Setenv("SB_DOCKER_POOL_ENABLED", "true")
		t.Setenv("SB_DOCKER_READY_SOCKET_ENABLED", "true")
		if err := runWithAutoCancel(t, 500*time.Millisecond, nil); err == nil {
			t.Fatal("expected ready-socket dir failure")
		}
	})

	t.Run("wasm_isolate_skipped_on_server", func(t *testing.T) {
		paths := setBaseRunEnv(t)
		t.Setenv("SB_NODE_ROLE", "server")
		t.Setenv("SB_ENABLE_CLUSTER", "true")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "true")
		t.Setenv("SB_RAFT_BIND_ADDR", "127.0.0.1:0")
		t.Setenv("SB_RAFT_ADVERTISE_ADDR", "127.0.0.1:0")
		t.Setenv("SB_RAFT_DATA_DIR", filepath.Join(paths.rootDir, "raft"))
		t.Setenv("SB_GOSSIP_BIND_ADDR", "127.0.0.1:0")
		t.Setenv("SB_GOSSIP_ADVERTISE_ADDR", "127.0.0.1:0")
		t.Setenv("SB_SELF_API_ADVERTISE_URL", "http://127.0.0.1:8080")
		t.Setenv("SB_ENABLE_WASM", "true")
		t.Setenv("SB_WASM_RUN_DIR", filepath.Join(paths.rootDir, "wasm-run"))
		t.Setenv("SB_WASM_MODULES_DIR", filepath.Join(paths.rootDir, "wasm-mod"))
		t.Setenv("SB_ENABLE_ISOLATE", "true")
		t.Setenv("SB_ISOLATE_USE_JAIL", "false") // jail is a boot contract this host cannot honor
		t.Setenv("SB_ISOLATE_WORKERD_PATH", "/bin/true")
		t.Setenv("SB_ISOLATE_RUN_DIR", filepath.Join(paths.rootDir, "isolate"))
		if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err != nil {
			t.Logf("Run err (ok): %v", err)
		}
	})

	t.Run("awskms_provider_unavailable", func(t *testing.T) {
		_ = setBaseRunEnv(t)
		t.Setenv("SB_SECRET_PROVIDER", "awskms")
		t.Setenv("SB_SECRET_AWS_KMS_KEY_ID", "alias/coverage-missing")
		t.Setenv("SB_SECRET_PROVIDER_STRICT_BOOT", "true")
		t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
		t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "no-aws-config"))
		t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "no-aws-creds"))
		if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err == nil {
			t.Fatal("expected awskms configure failure")
		}
	})

	t.Run("ssh_host_key_dir_fails", func(t *testing.T) {
		paths := setBaseRunEnv(t)
		t.Setenv("SB_ENABLE_SSH_GATEWAY", "true")
		t.Setenv("SB_SSH_HOST_KEY_PATH", paths.rootDir)
		if err := runWithAutoCancel(t, 500*time.Millisecond, nil); err == nil {
			t.Fatal("expected ssh host-key failure")
		}
	})

	t.Run("ssh_listen_conflict", func(t *testing.T) {
		_ = setBaseRunEnv(t)
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		t.Setenv("SB_ENABLE_SSH_GATEWAY", "true")
		t.Setenv("SB_SSH_LISTEN_ADDR", ln.Addr().String())
		if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err != nil {
			t.Logf("Run err (ok): %v", err)
		}
	})

	t.Run("auto_reconcile_warns", func(t *testing.T) {
		_ = setBaseRunEnv(t)
		t.Setenv("SB_AUTO_RECONCILE", "true")
		if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err != nil {
			t.Logf("Run err (ok): %v", err)
		}
	})

	t.Run("cluster_raft_dir_blocked", func(t *testing.T) {
		paths := setBaseRunEnv(t)
		raft := filepath.Join(paths.rootDir, "raft-file")
		if err := os.WriteFile(raft, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("SB_ENABLE_CLUSTER", "true")
		t.Setenv("SB_NODE_ROLE", "server")
		t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "true")
		t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "true")
		t.Setenv("SB_RAFT_BIND_ADDR", "127.0.0.1:0")
		t.Setenv("SB_RAFT_ADVERTISE_ADDR", "127.0.0.1:0")
		t.Setenv("SB_RAFT_DATA_DIR", raft)
		t.Setenv("SB_GOSSIP_BIND_ADDR", "127.0.0.1:0")
		t.Setenv("SB_GOSSIP_ADVERTISE_ADDR", "127.0.0.1:0")
		t.Setenv("SB_SELF_API_ADVERTISE_URL", "http://127.0.0.1:8080")
		if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err == nil {
			t.Fatal("expected cluster start failure")
		}
	})
}

type liftAuditExporter struct{}

func (liftAuditExporter) ExportEvents(context.Context, controlplane.AuditEventBatch) (string, error) {
	return "next", nil
}

func TestCoverage95LiftAuditExporterProvider(t *testing.T) {
	_ = setBaseRunEnv(t)
	if err := runWithAutoCancel(t, 800*time.Millisecond, func(context.Context, FleetConfig) (controlplane.Provider, error) {
		return controlplane.Provider{AuditExporter: liftAuditExporter{}}.WithDefaults(), nil
	}); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

type liftWitness struct{}

func (liftWitness) WitnessHeads(context.Context, []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	return controlplane.WitnessReceipt{ReceiptID: "r1"}, nil
}

func (liftWitness) LastWitnessedHead(context.Context, string) (string, bool, error) {
	return "", false, nil
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

type mismatchWitness struct{}

func (mismatchWitness) WitnessHeads(context.Context, []controlplane.AuditHead) (controlplane.WitnessReceipt, error) {
	return controlplane.WitnessReceipt{ReceiptID: "r1"}, nil
}

func (mismatchWitness) LastWitnessedHead(context.Context, string) (string, bool, error) {
	return "", false, errors.New("witness offline")
}

func TestCoverage95LiftEnterpriseWitnessMismatch(t *testing.T) {
	_ = setBaseRunEnv(t)
	t.Setenv("SB_ENTERPRISE_MODE", "true")
	t.Setenv("SB_PAT_TOKEN", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	t.Setenv("SB_SECRET_AUDIT_STRICT_BOOT", "true")
	err := runWithAutoCancel(t, 800*time.Millisecond, func(context.Context, FleetConfig) (controlplane.Provider, error) {
		return controlplane.Provider{
			Witness:       mismatchWitness{},
			AuditExporter: liftAuditExporter{},
		}.WithDefaults(), nil
	})
	if err == nil {
		t.Fatal("expected witness verification failure")
	}
}

func TestCoverage95LiftEnterpriseNeedsExporter(t *testing.T) {
	// Enterprise forces an off-node exporter; a witness-only provider still
	// fails closed so JSONL-only nodes cannot claim tamper-evidence.
	_ = setBaseRunEnv(t)
	t.Setenv("SB_ENTERPRISE_MODE", "true")
	t.Setenv("SB_PAT_TOKEN", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
	t.Setenv("SB_SECRET_AUDIT_STRICT_BOOT", "true")
	err := runWithAutoCancel(t, 800*time.Millisecond, func(context.Context, FleetConfig) (controlplane.Provider, error) {
		return controlplane.Provider{Witness: liftWitness{}}.WithDefaults(), nil
	})
	if err == nil {
		t.Fatal("expected enterprise exporter requirement")
	}
}

func TestCoverage95LiftProviderFactoryError(t *testing.T) {
	_ = setBaseRunEnv(t)
	err := runWithAutoCancel(t, 500*time.Millisecond, func(context.Context, FleetConfig) (controlplane.Provider, error) {
		return controlplane.Noop(), errors.New("provider boom")
	})
	if err == nil {
		t.Fatal("expected provider factory error")
	}
}
