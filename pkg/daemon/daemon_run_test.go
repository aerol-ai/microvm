package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

type runTestPaths struct {
	rootDir           string
	dbPath            string
	keyPath           string
	mountsRoot        string
	mountCredDir      string
	sshKeyPath        string
	clusterPATPath    string
	firecrackerKernel string
	firecrackerRunDir string
	templatesDir      string
	bypassMarkerPath  string
	internalL4WakeDir string
	toolboxMountPath  string
	clusterTLSDir     string
}

func writeTestClusterTLS(t *testing.T, rootDir string) string {
	t.Helper()
	dir := filepath.Join(rootDir, "cluster-tls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir cluster tls: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate cluster tls key: %v", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "aerolvm-test-cluster"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"aerolvm-cluster-node", "node:aerolvm-test-cluster"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cluster tls cert: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal cluster tls key: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	for name, data := range map[string][]byte{
		"ca.crt": certPEM, "node.crt": certPEM, "node.key": keyPEM,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	return dir
}

func setBaseRunEnv(t *testing.T) runTestPaths {
	t.Helper()

	rootDir := t.TempDir()
	dbDir := filepath.Join(rootDir, "db")
	if err := os.MkdirAll(dbDir, 0o755); err != nil {
		t.Fatalf("mkdir db dir: %v", err)
	}

	paths := runTestPaths{
		rootDir:           rootDir,
		dbPath:            filepath.Join(dbDir, "state.db"),
		keyPath:           filepath.Join(rootDir, "credential.key"),
		mountsRoot:        filepath.Join(rootDir, "mounts"),
		mountCredDir:      filepath.Join(rootDir, "mount-creds"),
		sshKeyPath:        filepath.Join(rootDir, "ssh_host_ed25519_key"),
		clusterPATPath:    filepath.Join(rootDir, "cluster.pat"),
		firecrackerKernel: filepath.Join(rootDir, "vmlinux"),
		firecrackerRunDir: filepath.Join(rootDir, "firecracker-run"),
		templatesDir:      filepath.Join(rootDir, "templates"),
		internalL4WakeDir: filepath.Join(rootDir, "l4wake"),
		toolboxMountPath:  "/usr/local/bin/toolboxd",
	}
	paths.clusterTLSDir = writeTestClusterTLS(t, rootDir)
	paths.bypassMarkerPath = filepath.Join(filepath.Dir(paths.dbPath), "bypass_last_enabled")

	if err := os.WriteFile(paths.clusterPATPath, []byte("cluster-pat-token\n"), 0o600); err != nil {
		t.Fatalf("write cluster pat: %v", err)
	}
	if err := os.WriteFile(paths.firecrackerKernel, []byte("fake kernel"), 0o600); err != nil {
		t.Fatalf("write firecracker kernel: %v", err)
	}

	t.Setenv("SB_PAT_TOKEN", "test-token")
	t.Setenv("SB_NODE_ID", "aerolvm-test-cluster")
	t.Setenv("SB_PUBLIC_HOST", "127.0.0.1")
	t.Setenv("SB_API_HOST", "127.0.0.1")
	t.Setenv("SB_API_PORT", "0")
	t.Setenv("SB_DB_PATH", paths.dbPath)
	t.Setenv("SB_TOOLBOX_BINARY_PATH", "/bin/true")
	t.Setenv("SB_TOOLBOX_MOUNT_PATH", paths.toolboxMountPath)
	t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY_PATH", paths.keyPath)
	t.Setenv("SB_CLUSTER_TLS_DIR", paths.clusterTLSDir)
	t.Setenv("SB_MOUNTS_ROOT", paths.mountsRoot)
	t.Setenv("SB_MOUNTS_CRED_DIR", paths.mountCredDir)
	t.Setenv("SB_HTTP_CLIENT_TIMEOUT", "200ms")
	t.Setenv("SB_ENABLE_NETWORK_RULES", "false")
	t.Setenv("SB_AUTO_RECONCILE", "false")
	t.Setenv("SB_ENABLE_CADDY", "false")
	t.Setenv("SB_ENABLE_EVENT_MONITOR", "false")
	t.Setenv("SB_ENABLE_SERVERLESS", "false")
	t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "false")
	t.Setenv("SB_ENABLE_SSH_GATEWAY", "false")
	t.Setenv("SB_ENABLE_FIRECRACKER", "false")
	t.Setenv("SB_IMAGE_BUILD_GC_ENABLED", "false")
	t.Setenv("SB_AUTO_IMPORT_ENABLED", "false")
	t.Setenv("SB_SNAPSHOT_PUSH_ENABLED", "false")
	t.Setenv("SB_DOMAIN", "")
	t.Setenv("SB_CADDY_ADMIN_URL", "http://127.0.0.1:2019")
	t.Setenv("SB_INTERNAL_INGRESS_ADDR", "127.0.0.1:0")
	t.Setenv("SB_INTERNAL_L4_WAKE_ADDR", "127.0.0.1:0")
	t.Setenv("SB_INTERNAL_L4_WAKE_DIR", paths.internalL4WakeDir)
	t.Setenv("SB_SSH_LISTEN_ADDR", "127.0.0.1:0")
	t.Setenv("SB_SSH_HOST_KEY_PATH", paths.sshKeyPath)

	return paths
}

func runWithAutoCancel(t *testing.T, delay time.Duration, makeProvider ProviderFactory) error {
	t.Helper()
	if delay < 500*time.Millisecond {
		delay = 500 * time.Millisecond
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stop := time.AfterFunc(delay, cancel)
	t.Cleanup(func() { stop.Stop() })

	return Run(ctx, testLogger(), makeProvider)
}

func TestRun_GracefulShutdownWithProviderAndSSH(t *testing.T) {
	paths := setBaseRunEnv(t)
	t.Setenv("SB_ENABLE_SSH_GATEWAY", "true")

	providerCalls := 0
	err := runWithAutoCancel(t, 150*time.Millisecond, func(ctx context.Context, fc FleetConfig) (controlplane.Provider, error) {
		providerCalls++
		if fc.Enabled {
			t.Fatalf("provider received Enabled=true, want false for default config")
		}
		if fc.Endpoint != "" || fc.Token != "" {
			t.Fatalf("provider received unexpected fleet config: %+v", fc)
		}
		return controlplane.Noop(), nil
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if providerCalls != 1 {
		t.Fatalf("provider calls = %d, want 1", providerCalls)
	}
	if _, err := os.Stat(paths.keyPath); err != nil {
		t.Fatalf("credential key not created: %v", err)
	}
	if _, err := os.Stat(paths.sshKeyPath); err != nil {
		t.Fatalf("ssh host key not created: %v", err)
	}
	if got := readBypassMarker(paths.bypassMarkerPath); got {
		t.Fatalf("bypass marker = true, want false on default boot")
	}
}

func TestRun_GracefulShutdownWithFirecrackerServerlessAndCustomDomains(t *testing.T) {
	paths := setBaseRunEnv(t)

	t.Setenv("SB_ENABLE_CADDY", "true")
	t.Setenv("SB_CADDY_ADMIN_URL", "http://127.0.0.1:1")
	t.Setenv("SB_ENABLE_SERVERLESS", "true")
	t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "true")
	t.Setenv("SB_DOMAIN", "example.test")
	t.Setenv("SB_ENABLE_SSH_GATEWAY", "true")
	t.Setenv("SB_AUTO_RECONCILE", "true")
	t.Setenv("SB_AUTO_IMPORT_ENABLED", "true")
	t.Setenv("SB_AUTO_IMPORT_HOOKS_URL", "https://hooks.example")
	t.Setenv("SB_AUTO_IMPORT_CLUSTER_ID", "cluster-1")
	t.Setenv("SB_AUTO_IMPORT_CLUSTER_PAT_PATH", paths.clusterPATPath)
	t.Setenv("SB_AUTO_IMPORT_RECONCILE_INTERVAL", "5ms")
	t.Setenv("SB_AUTO_IMPORT_MAX_IN_FLIGHT", "1")
	t.Setenv("SB_SNAPSHOT_PUSH_ENABLED", "true")
	t.Setenv("SB_SNAPSHOT_PUSH_RECONCILE_INTERVAL", "5ms")
	t.Setenv("SB_SNAPSHOT_PUSH_MAX_IN_FLIGHT", "1")
	t.Setenv("SB_ENABLE_FIRECRACKER", "true")
	t.Setenv("SB_FIRECRACKER_BINARY", "/bin/true")
	t.Setenv("SB_JAILER_BINARY", "/bin/true")
	t.Setenv("SB_FIRECRACKER_KERNEL", paths.firecrackerKernel)
	t.Setenv("SB_FIRECRACKER_RUN_DIR", paths.firecrackerRunDir)
	t.Setenv("SB_FIRECRACKER_TEMPLATES_DIR", paths.templatesDir)
	t.Setenv("SB_FIRECRACKER_USE_JAILER", "false")
	t.Setenv("SB_FIRECRACKER_TAP_BASE_CIDR", "172.19.0.0/30")
	t.Setenv("SB_FIRECRACKER_TAP_POOL_SIZE", "1")
	t.Setenv("SB_FIRECRACKER_SKOPEO_BIN", "/bin/true")
	t.Setenv("SB_FIRECRACKER_UMOCI_BIN", "/bin/true")
	t.Setenv("SB_FIRECRACKER_MKFS_BIN", "/bin/true")
	t.Setenv("SB_FIRECRACKER_VMM_POOL_ENABLED", "true")
	t.Setenv("SB_FIRECRACKER_VMM_POOL_DEPTH_DEFAULT", "1")
	t.Setenv("SB_FIRECRACKER_TEMPLATE_ROTATION_INTERVAL", "5ms")
	t.Setenv("SB_FIRECRACKER_TEMPLATE_MAX_AGE", "24h")

	if err := os.WriteFile(paths.bypassMarkerPath, []byte("true\n"), 0o644); err != nil {
		t.Fatalf("seed bypass marker: %v", err)
	}

	err := runWithAutoCancel(t, 200*time.Millisecond, nil)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if got := readBypassMarker(paths.bypassMarkerPath); got {
		t.Fatalf("bypass marker = true after rollback boot, want false")
	}
	if _, err := os.Stat(paths.keyPath); err != nil {
		t.Fatalf("credential key not created: %v", err)
	}
	if _, err := os.Stat(paths.sshKeyPath); err != nil {
		t.Fatalf("ssh host key not created: %v", err)
	}
}

func TestRun_GracefulShutdownWithOTELExporters(t *testing.T) {
	setBaseRunEnv(t)

	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer collector.Close()

	t.Setenv("SB_OTEL_TRACES_ENABLED", "true")
	t.Setenv("SB_OTEL_TRACES_ENDPOINT", collector.URL)
	t.Setenv("SB_OTEL_TRACES_SAMPLE_RATIO", "1")
	t.Setenv("SB_OTEL_METRICS_ENABLED", "true")
	t.Setenv("SB_OTEL_METRICS_ENDPOINT", collector.URL)
	t.Setenv("SB_OTEL_METRICS_INTERVAL", "10ms")

	if err := runWithAutoCancel(t, 150*time.Millisecond, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRun_OTELErrorsAreNonFatal(t *testing.T) {
	setBaseRunEnv(t)

	badEndpoint := "http://[::1"
	t.Setenv("SB_OTEL_TRACES_ENABLED", "true")
	t.Setenv("SB_OTEL_TRACES_ENDPOINT", badEndpoint)
	t.Setenv("SB_OTEL_METRICS_ENABLED", "true")
	t.Setenv("SB_OTEL_METRICS_ENDPOINT", badEndpoint)

	if err := runWithAutoCancel(t, 100*time.Millisecond, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRun_CipherInitializationErrorReturnsWrappedError(t *testing.T) {
	setBaseRunEnv(t)
	t.Setenv("SB_CREDENTIAL_ENCRYPTION_KEY", "not-base64")

	err := Run(context.Background(), testLogger(), nil)
	if err == nil {
		t.Fatal("Run returned nil error, want credential cipher failure")
	}
	if !strings.Contains(err.Error(), "initialize credential cipher") {
		t.Fatalf("Run error = %v, want initialize credential cipher wrapper", err)
	}
}

func TestRun_MountManagerErrorReturnsWrappedError(t *testing.T) {
	setBaseRunEnv(t)
	t.Setenv("SB_MOUNTS_ROOT", "relative-mounts-root")

	err := Run(context.Background(), testLogger(), nil)
	if err == nil {
		t.Fatal("Run returned nil error, want mount manager failure")
	}
	if !strings.Contains(err.Error(), "initialize mount manager") {
		t.Fatalf("Run error = %v, want initialize mount manager wrapper", err)
	}
}

func TestRun_GracefulShutdownWithFleetEnabled(t *testing.T) {
	setBaseRunEnv(t)
	t.Setenv("SB_FLEET_ENABLED", "true")
	t.Setenv("SB_FLEET_ENDPOINT", "https://fleet.example")
	t.Setenv("SB_FLEET_TOKEN", "fleet-token")
	t.Setenv("SB_FLEET_LIVE_SAMPLE_INTERVAL", "10ms")

	err := runWithAutoCancel(t, 150*time.Millisecond, func(_ context.Context, fc FleetConfig) (controlplane.Provider, error) {
		if !fc.Enabled {
			t.Fatal("fleet config Enabled = false, want true")
		}
		if fc.Endpoint != "https://fleet.example" || fc.Token != "fleet-token" {
			t.Fatalf("unexpected fleet config: %+v", fc)
		}
		return controlplane.Noop(), nil
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRun_GracefulShutdownClusterServerIngress(t *testing.T) {
	setBaseRunEnv(t)

	t.Setenv("SB_NODE_ROLE", "server,ingress")
	t.Setenv("SB_ENABLE_CLUSTER", "true")
	t.Setenv("SB_CLUSTER_BOOTSTRAP", "true")
	t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "true")
	t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "true")
	t.Setenv("SB_RAFT_BIND_ADDR", "127.0.0.1:0")
	t.Setenv("SB_GOSSIP_BIND_ADDR", "127.0.0.1:0")
	t.Setenv("SB_RAFT_ADVERTISE_ADDR", "127.0.0.1:0")
	t.Setenv("SB_GOSSIP_ADVERTISE_ADDR", "127.0.0.1:0")
	// Let the kernel allocate the internal-listener port atomically. Picking a
	// free port and closing the probe socket creates a TOCTOU race with other CI
	// jobs and was intermittently colliding before Run could bind it.
	t.Setenv("SB_CLUSTER_INTERNAL_LISTEN", "127.0.0.1:0")
	t.Setenv("SB_CLUSTER_INTERNAL_ADVERTISE", "https://127.0.0.1:21443")

	if err := runWithAutoCancel(t, 200*time.Millisecond, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRun_GracefulShutdownWithHostCapacityOverrides(t *testing.T) {
	setBaseRunEnv(t)
	t.Setenv("SB_HOST_CPU_CORES", "8")
	t.Setenv("SB_HOST_MEMORY_MB", "16384")
	t.Setenv("SB_HOST_DISK_GB", "100")
	t.Setenv("SB_HOST_GPU_COUNT", "1")
	t.Setenv("SB_HOST_GPU_VENDOR", "nvidia")

	if err := runWithAutoCancel(t, 120*time.Millisecond, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRun_GracefulShutdownWithClusterBootstrap(t *testing.T) {
	paths := setBaseRunEnv(t)

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

	if err := runWithAutoCancel(t, 250*time.Millisecond, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRun_GracefulShutdownWithMirrorEnabled(t *testing.T) {
	paths := setBaseRunEnv(t)
	t.Setenv("SB_MIRROR_HOST", "mirror.example")
	t.Setenv("SB_MIRROR_UPSTREAMS", "docker.io:dockerhub")
	t.Setenv("SB_UPSTREAM_WRAP_KEY_PATH", writeWrapKeyFile(t))

	if err := runWithAutoCancel(t, 150*time.Millisecond, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	_ = paths
}

func TestRun_GracefulShutdownWithWasmEnabled(t *testing.T) {
	paths := setBaseRunEnv(t)

	wasmRunDir := filepath.Join(paths.rootDir, "wasm-run")
	wasmModulesDir := filepath.Join(paths.rootDir, "wasm-modules")
	if err := os.MkdirAll(wasmRunDir, 0o755); err != nil {
		t.Fatalf("mkdir wasm run: %v", err)
	}
	if err := os.MkdirAll(wasmModulesDir, 0o755); err != nil {
		t.Fatalf("mkdir wasm modules: %v", err)
	}

	t.Setenv("SB_ENABLE_WASM", "true")
	t.Setenv("SB_WASM_RUN_DIR", wasmRunDir)
	t.Setenv("SB_WASM_MODULES_DIR", wasmModulesDir)
	t.Setenv("SB_WASM_POOL_ENABLED", "true")
	t.Setenv("SB_WASM_POOL_DEPTH_DEFAULT", "1")
	t.Setenv("SB_WASM_POOL_REFILL_INTERVAL", "5ms")
	t.Setenv("SB_WASM_STATEKV_WRITES_PER_SEC", "10")
	t.Setenv("SB_WASM_STATEKV_BURST", "20")

	if err := runWithAutoCancel(t, 200*time.Millisecond, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRun_NetstatsBootstrapErrorIsNonFatal(t *testing.T) {
	setBaseRunEnv(t)
	t.Setenv("SB_NETSTATS_POLL_INTERVAL", "0s")

	if err := runWithAutoCancel(t, 100*time.Millisecond, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRun_SSHGatewayWithCluster(t *testing.T) {
	paths := setBaseRunEnv(t)

	t.Setenv("SB_ENABLE_SSH_GATEWAY", "true")
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

	if err := runWithAutoCancel(t, 200*time.Millisecond, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRun_ClusterWorkerWithFirecracker(t *testing.T) {
	paths := setBaseRunEnv(t)

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
	t.Setenv("SB_ENABLE_FIRECRACKER", "true")
	t.Setenv("SB_FIRECRACKER_BINARY", "/bin/true")
	t.Setenv("SB_JAILER_BINARY", "/bin/true")
	t.Setenv("SB_FIRECRACKER_KERNEL", paths.firecrackerKernel)
	t.Setenv("SB_FIRECRACKER_RUN_DIR", paths.firecrackerRunDir)
	t.Setenv("SB_FIRECRACKER_TEMPLATES_DIR", paths.templatesDir)
	t.Setenv("SB_FIRECRACKER_USE_JAILER", "false")
	t.Setenv("SB_FIRECRACKER_TAP_BASE_CIDR", "172.19.0.0/30")
	t.Setenv("SB_FIRECRACKER_TAP_POOL_SIZE", "1")
	t.Setenv("SB_FIRECRACKER_SKOPEO_BIN", "/bin/true")
	t.Setenv("SB_FIRECRACKER_UMOCI_BIN", "/bin/true")
	t.Setenv("SB_FIRECRACKER_MKFS_BIN", "/bin/true")

	if err := runWithAutoCancel(t, 200*time.Millisecond, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRun_PlatformVolumesS3(t *testing.T) {
	paths := setBaseRunEnv(t)
	t.Setenv("SB_PLATFORM_VOLUMES_ENABLED", "true")
	t.Setenv("SB_PLATFORM_VOLUMES_BACKEND", "s3")
	t.Setenv("SB_PLATFORM_VOLUMES_S3_BUCKET", "test-bucket")
	t.Setenv("SB_PLATFORM_VOLUMES_RECLAIM_INTERVAL", "1h")
	t.Setenv("SB_PLATFORM_VOLUMES_RECLAIM_MOUNT_ROOT", filepath.Join(paths.rootDir, "volume-reclaim"))

	if err := runWithAutoCancel(t, 150*time.Millisecond, nil); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}

func TestRun_FirecrackerTapSeedFailure(t *testing.T) {
	paths := setBaseRunEnv(t)
	t.Setenv("SB_ENABLE_FIRECRACKER", "true")
	t.Setenv("SB_FIRECRACKER_BINARY", "/bin/true")
	t.Setenv("SB_JAILER_BINARY", "/bin/true")
	t.Setenv("SB_FIRECRACKER_KERNEL", paths.firecrackerKernel)
	t.Setenv("SB_FIRECRACKER_RUN_DIR", paths.firecrackerRunDir)
	t.Setenv("SB_FIRECRACKER_USE_JAILER", "false")
	t.Setenv("SB_FIRECRACKER_TAP_BASE_CIDR", "172.19.0.0/30")
	t.Setenv("SB_FIRECRACKER_TAP_POOL_SIZE", "999999")
	t.Setenv("SB_FIRECRACKER_SKOPEO_BIN", "/bin/true")
	t.Setenv("SB_FIRECRACKER_UMOCI_BIN", "/bin/true")
	t.Setenv("SB_FIRECRACKER_MKFS_BIN", "/bin/true")

	err := Run(context.Background(), testLogger(), nil)
	if err == nil {
		t.Fatal("Run returned nil error, want firecracker tap pool seed failure")
	}
	if !strings.Contains(err.Error(), "firecracker tap pool seed") {
		t.Fatalf("Run error = %v, want tap pool seed wrapper", err)
	}
}

func TestStartAutoImportReconciler_ImporterBuildError(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	patPath := filepath.Join(t.TempDir(), "cluster.pat")
	if err := os.WriteFile(patPath, []byte("cluster-pat\n"), 0o600); err != nil {
		t.Fatalf("write pat: %v", err)
	}

	startAutoImportReconciler(t.Context(), testLogger(), config.Config{
		AutoImportEnabled:        true,
		AutoImportClusterPATPath: patPath,
		AutoImportHooksBaseURL:   "http://[::1",
		AutoImportClusterID:      "cluster-1",
	}, st, svc)
}

func TestStartSnapshotPushReconciler_PusherBuildError(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)

	startSnapshotPushReconciler(t.Context(), testLogger(), config.Config{
		SnapshotPushEnabled:           true,
		MirrorPushHost:                "push.example",
		AutoImportClusterID:           "",
		AutoImportClusterPATPath:      "",
		SnapshotPushReconcileInterval: 5 * time.Millisecond,
	}, st, svc, nil, nil)
}

func TestStartTemplateArtifactPushReconciler_PusherBuildError(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)

	startTemplateArtifactPushReconciler(t.Context(), testLogger(), config.Config{
		EnableFirecracker:             true,
		SnapshotPushEnabled:           true,
		MirrorPushHost:                "push.example",
		AutoImportClusterID:           "",
		AutoImportClusterPATPath:      "",
		FirecrackerTemplatesDir:       t.TempDir(),
		SnapshotPushReconcileInterval: 5 * time.Millisecond,
	}, st, svc, nil)
}

func TestAttachTemplateArtifactPuller_BuildError(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)

	attachTemplateArtifactPuller(testLogger(), config.Config{
		EnableFirecracker:       true,
		FirecrackerTemplatesDir: t.TempDir(),
	}, svc, nil)
}

func TestStartTemplateRotationReconciler_EnabledSweep(t *testing.T) {
	ctx := context.Background()
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)

	now := time.Now().UTC()
	stale := now.Add(-48 * time.Hour)
	if err := st.CreateTemplate(ctx, &models.Template{
		ID: "tpl-rotate", Image: "docker://alpine:3.19",
		Status: models.TemplateStatusReady, ReadyAt: &stale,
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}

	startTemplateRotationReconciler(t.Context(), testLogger(), config.Config{
		EnableFirecracker:                   true,
		FirecrackerTemplateRotationInterval: 5 * time.Millisecond,
		FirecrackerTemplateMaxAge:           time.Hour,
	}, st, svc)
	time.Sleep(25 * time.Millisecond)
}

func TestStartTemplateRotationReconciler_ReconcilerBuildError(t *testing.T) {
	st := openTestStore(t)
	startTemplateRotationReconciler(t.Context(), testLogger(), config.Config{
		EnableFirecracker:                   true,
		FirecrackerTemplateRotationInterval: time.Second,
		FirecrackerTemplateMaxAge:           time.Hour,
	}, st, nil)
}

func TestStartTemplateRotationReconciler_IntervalWithoutMaxAge(t *testing.T) {
	st := openTestStore(t)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)

	startTemplateRotationReconciler(t.Context(), testLogger(), config.Config{
		EnableFirecracker:                   true,
		FirecrackerTemplateRotationInterval: 5 * time.Millisecond,
		FirecrackerTemplateMaxAge:           0,
	}, st, svc)
}
