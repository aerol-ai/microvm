package daemon

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// Run branches that only log (and so stay invisible to the boot-failure
// tests), plus the refanout retry's hard-failure arm. Every Run here points DOCKER_HOST at a socket that does
// not exist, so the boot never reaches a real Docker daemon and the
// docker-backed boot steps take their failure paths deterministically.

// syncBuffer is an io.Writer safe for the daemon's concurrent loggers.
type syncBuffer struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// runCapturingLogs is runWithAutoCancel with the daemon's log kept for
// assertions.
func runCapturingLogs(t *testing.T, delay time.Duration) (error, string) {
	t.Helper()
	var buf syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	stop := time.AfterFunc(delay, cancel)
	t.Cleanup(func() { stop.Stop() })
	err := Run(ctx, slog.New(slog.NewTextHandler(&buf, nil)), nil)
	return err, buf.String()
}

func setNoDockerEnv(t *testing.T, paths runTestPaths) {
	t.Helper()
	t.Setenv("DOCKER_HOST", "unix://"+filepath.Join(paths.rootDir, "no-docker.sock"))
}

// setClusterAgentEnv makes this node a non-bootstrap cluster member pointed
// at a peer that is not there: the agent starts, but no leader is ever seated.
func setClusterAgentEnv(t *testing.T, role string) {
	t.Helper()
	t.Setenv("SB_ENABLE_CLUSTER", "true")
	t.Setenv("SB_NODE_ROLE", role)
	t.Setenv("SB_CLUSTER_BOOTSTRAP", "false")
	t.Setenv("SB_BOOTSTRAP_PEERS", "127.0.0.1:19999")
	t.Setenv("SB_CLUSTER_INSECURE_GOSSIP", "true")
	t.Setenv("SB_CLUSTER_INSECURE_CREDENTIALS", "true")
	t.Setenv("SB_RAFT_BIND_ADDR", "127.0.0.1:0")
	t.Setenv("SB_GOSSIP_BIND_ADDR", "127.0.0.1:0")
	t.Setenv("SB_RAFT_ADVERTISE_ADDR", "127.0.0.1:0")
	t.Setenv("SB_GOSSIP_ADVERTISE_ADDR", "127.0.0.1:0")
	t.Setenv("SB_SELF_API_ADVERTISE_URL", "http://127.0.0.1:8080")
}

func TestCov96RunAuditExportBackendOpenFails(t *testing.T) {
	paths := setBaseRunEnv(t)
	setNoDockerEnv(t, paths)
	blocker := filepath.Join(paths.rootDir, "audit-blocker")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SB_AUDIT_EXPORT_BACKEND", "file")
	t.Setenv("SB_AUDIT_EXPORT_FILE_PATH", filepath.Join(blocker, "audit.ndjson"))

	err := runWithAutoCancel(t, 500*time.Millisecond, nil)
	if err == nil || !strings.Contains(err.Error(), "configure audit export connector") {
		t.Fatalf("Run = %v, want audit export connector failure", err)
	}
}

func TestCov96RunDockerUnreachableIsNonFatal(t *testing.T) {
	paths := setBaseRunEnv(t)
	setNoDockerEnv(t, paths)
	t.Setenv("SB_DOCKER_POOL_ENABLED", "true")
	t.Setenv("SB_DOCKER_READY_SOCKET_ENABLED", "true")
	t.Setenv("SB_AUTO_RECONCILE", "true")
	t.Setenv("SB_INGRESS_PROXY_ROUTING", "true")

	err, logs := runCapturingLogs(t, 600*time.Millisecond)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, want := range []string{"ready socket sweep failed", "initial reconcile failed"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %q", want)
		}
	}
}

func TestCov96RunIngressOnlyProxyRoutingSkipsOnDemandTLS(t *testing.T) {
	paths := setBaseRunEnv(t)
	setNoDockerEnv(t, paths)
	setClusterAgentEnv(t, "ingress")
	t.Setenv("SB_ENABLE_CADDY", "true")
	t.Setenv("SB_CADDY_ADMIN_URL", "http://127.0.0.1:1")
	t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "true")
	t.Setenv("SB_DOMAIN", "example.test")
	t.Setenv("SB_INGRESS_PROXY_ROUTING", "true")

	err, logs := runCapturingLogs(t, 800*time.Millisecond)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(logs, "caddy on-demand TLS policy skipped") {
		t.Fatal("ingress-only proxy-routing node installed the on-demand TLS policy")
	}
}

func TestCov96RunCustomDomainsInstallsOnDemandTLS(t *testing.T) {
	paths := setBaseRunEnv(t)
	setNoDockerEnv(t, paths)
	var (
		mu       sync.Mutex
		onDemand bool
	)
	caddyAdmin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/config/apps/tls/automation/on_demand" {
			mu.Lock()
			onDemand = true
			mu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("null"))
	}))
	t.Cleanup(caddyAdmin.Close)
	t.Setenv("SB_ENABLE_CADDY", "true")
	t.Setenv("SB_CADDY_ADMIN_URL", caddyAdmin.URL)
	t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "true")
	t.Setenv("SB_DOMAIN", "example.test")

	err, logs := runCapturingLogs(t, 800*time.Millisecond)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !onDemand || !strings.Contains(logs, "caddy on-demand TLS policy installed") {
		t.Fatalf("on-demand PUT seen=%v; log lacks install line", onDemand)
	}
}

// A worker that restarts into a cluster with no leader seated must keep
// serving: ownership replay moves to a background retry, and outside
// enterprise mode a failed durable-secret re-fanout is logged, not fatal.
func TestCov96RunClusterWorkerDefersLeaderWork(t *testing.T) {
	paths := setBaseRunEnv(t)
	setNoDockerEnv(t, paths)
	setClusterAgentEnv(t, "worker")

	st, err := store.Open(paths.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-replay-boot", Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		Runtime: models.RuntimeDocker, CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PutClusterSecret(ctx, store.ClusterSecretRecord{
		Ref:       secrets.FormatRef("sb-replay-boot", "inc-a", secrets.RefVersion),
		SandboxID: "sb-replay-boot", Version: secrets.RefVersion,
		Recipients:    []string{"aerolvm-test-cluster", "node-b"},
		SealedPayload: []byte("sealed"), SealGeneration: 1,
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	err, logs := runCapturingLogs(t, 800*time.Millisecond)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, want := range []string{"ownership", "secret re-fanout at boot"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %q; logs:\n%s", want, logs)
		}
	}
}

func TestCov96RunClusterHeartbeatInventoryProviders(t *testing.T) {
	paths := setBaseRunEnv(t)
	setNoDockerEnv(t, paths)
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
	// The capacity-lease loop invokes the template + wasm inventory
	// callbacks on every tick; a short interval makes them run in-window.
	t.Setenv("SB_CAPACITY_GOSSIP_INTERVAL", "10ms")
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
	t.Setenv("SB_ENABLE_WASM", "true")
	t.Setenv("SB_WASM_RUN_DIR", filepath.Join(paths.rootDir, "wasm-run"))
	t.Setenv("SB_WASM_MODULES_DIR", filepath.Join(paths.rootDir, "wasm-modules"))

	if err := runWithAutoCancel(t, 800*time.Millisecond, nil); err != nil {
		t.Fatalf("Run: %v", err)
	}
}

// A refanout retry that fails for a reason other than a missing leader keeps
// saying so on every tick rather than looping silently.
func TestCov96RefanoutRetryLogsHardFailure(t *testing.T) {
	oldTick := clusterOwnershipReplayTick
	clusterOwnershipReplayTick = 5 * time.Millisecond
	t.Cleanup(func() { clusterOwnershipReplayTick = oldTick })

	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	svc := service.New(config.Config{EnableCluster: true}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	svc.AttachCluster(cluster.NewNoop("node-a", "http://node-a", ""))
	_ = st.Close() // every secret listing now fails with a non-leader error

	var buf syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startClusterSecretRefanoutRetry(ctx, svc, slog.New(slog.NewTextHandler(&buf, nil)))

	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(buf.String(), "secret re-fanout retry failed") {
		if time.Now().After(deadline) {
			t.Fatalf("retry never reported the hard failure; log:\n%s", buf.String())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if strings.Contains(buf.String(), "completed on retry") {
		t.Fatal("retry claimed success against a closed store")
	}
}
