package service

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/runtime"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

type pushErrorRuntime struct {
	*recordingRuntime
	pushErr error
}

func (r *pushErrorRuntime) PushAllowedPorts(_ context.Context, containerIP, toolboxToken string, ports []int) error {
	copyPorts := append([]int(nil), ports...)
	r.pushes = append(r.pushes, allowedPortsPush{containerIP: containerIP, token: toolboxToken, ports: copyPorts})
	return r.pushErr
}

type routeAdminCaddyFake struct {
	mu             sync.Mutex
	httpRouteIDs   map[string]struct{}
	l4TCPServerIDs map[string]struct{}
	l4TLSRouteIDs  map[string]struct{}
	afterMutation  func(method, path, id string)
}

func newRouteAdminCaddyFake() *routeAdminCaddyFake {
	return &routeAdminCaddyFake{
		httpRouteIDs:   map[string]struct{}{},
		l4TCPServerIDs: map[string]struct{}{},
		l4TLSRouteIDs:  map[string]struct{}{},
	}
}

func (f *routeAdminCaddyFake) handler(t *testing.T) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/id/"):
			id := strings.TrimPrefix(r.URL.Path, "/id/")
			switch r.Method {
			case http.MethodPatch:
				f.mu.Lock()
				_, httpOK := f.httpRouteIDs[id]
				_, tlsOK := f.l4TLSRouteIDs[id]
				f.mu.Unlock()
				if !httpOK && !tlsOK {
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				if f.afterMutation != nil {
					f.afterMutation(r.Method, r.URL.Path, id)
				}
				w.WriteHeader(http.StatusOK)
			case http.MethodDelete:
				f.mu.Lock()
				if _, ok := f.httpRouteIDs[id]; ok {
					delete(f.httpRouteIDs, id)
					f.mu.Unlock()
					if f.afterMutation != nil {
						f.afterMutation(r.Method, r.URL.Path, id)
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				if _, ok := f.l4TLSRouteIDs[id]; ok {
					delete(f.l4TLSRouteIDs, id)
					f.mu.Unlock()
					if f.afterMutation != nil {
						f.afterMutation(r.Method, r.URL.Path, id)
					}
					w.WriteHeader(http.StatusOK)
					return
				}
				f.mu.Unlock()
				http.Error(w, "not found", http.StatusNotFound)
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}

		case r.Method == http.MethodPut && r.URL.Path == "/config/apps/http/servers/srv0/routes/0":
			var route map[string]any
			if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
				t.Fatalf("decode http route: %v", err)
			}
			id, _ := route["@id"].(string)
			if id == "" {
				t.Fatal("inserted http route missing @id")
			}
			f.mu.Lock()
			f.httpRouteIDs[id] = struct{}{}
			f.mu.Unlock()
			if f.afterMutation != nil {
				f.afterMutation(r.Method, r.URL.Path, id)
			}
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodPut && r.URL.Path == "/config/apps/layer4/servers/tls-mux/routes/0":
			var route map[string]any
			if err := json.NewDecoder(r.Body).Decode(&route); err != nil {
				t.Fatalf("decode tls route: %v", err)
			}
			id, _ := route["@id"].(string)
			if id == "" {
				t.Fatal("inserted tls route missing @id")
			}
			f.mu.Lock()
			f.l4TLSRouteIDs[id] = struct{}{}
			f.mu.Unlock()
			if f.afterMutation != nil {
				f.afterMutation(r.Method, r.URL.Path, id)
			}
			w.WriteHeader(http.StatusOK)

		case strings.HasPrefix(r.URL.Path, "/config/apps/layer4/servers/"):
			serverID := strings.TrimPrefix(r.URL.Path, "/config/apps/layer4/servers/")
			switch r.Method {
			case http.MethodPut, http.MethodPost:
				f.mu.Lock()
				f.l4TCPServerIDs[serverID] = struct{}{}
				f.mu.Unlock()
				if f.afterMutation != nil {
					f.afterMutation(r.Method, r.URL.Path, serverID)
				}
				w.WriteHeader(http.StatusOK)
			case http.MethodDelete:
				f.mu.Lock()
				if _, ok := f.l4TCPServerIDs[serverID]; !ok {
					f.mu.Unlock()
					http.Error(w, "not found", http.StatusNotFound)
					return
				}
				delete(f.l4TCPServerIDs, serverID)
				f.mu.Unlock()
				if f.afterMutation != nil {
					f.afterMutation(r.Method, r.URL.Path, serverID)
				}
				w.WriteHeader(http.StatusOK)
			default:
				t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
			}

		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	})
}

func (f *routeAdminCaddyFake) hasHTTPRoute(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.httpRouteIDs[id]
	return ok
}

func (f *routeAdminCaddyFake) hasTCPServer(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.l4TCPServerIDs[id]
	return ok
}

func (f *routeAdminCaddyFake) hasTLSRoute(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.l4TLSRouteIDs[id]
	return ok
}

func sqliteDSNForTest(path string) string {
	options := url.Values{}
	options.Set("_busy_timeout", "5000")
	options.Set("_foreign_keys", "on")
	options.Set("_journal_mode", "WAL")
	return path + "?" + options.Encode()
}

func newServiceRuntimeHarnessAtPath(t *testing.T, dbPath string, driver runtime.Runtime) (*Service, *storepkg.Store, *capacity.Admitter) {
	t.Helper()
	st, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() {
		_ = st.Close()
	})
	cipher := newTestCipher(t)
	st.SetSecretCipher(cipher)

	mgr, err := mounts.New(slog.New(slog.NewTextHandler(io.Discard, nil)), mounts.Config{
		RootDir:     filepath.Join(t.TempDir(), "mounts"),
		CredDir:     filepath.Join(t.TempDir(), "cred"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)

	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 8, MemoryTotalMB: 16384},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)

	svc := &Service{
		cfg: config.Config{
			Runtime:           models.RuntimeDocker,
			ToolboxPort:       4321,
			EnableCaddy:       false,
			HTTPClientTimeout: time.Second,
		},
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:          st,
		docker:         driver,
		caddy:          caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second}),
		mounts:         mgr,
		admitter:       admitter,
		images:         newDefaultImageDistributionProvider(""),
		cipher:         cipher,
		secretProvider: secrets.NewLocalProvider(cipher, newSecretBlobStore(st)),
	}
	return svc, st, admitter
}

func TestExposePortHTTPReplacementKeepsExistingExposureOnClusterFailure(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	fake := newRouteAdminCaddyFake()
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc.cfg = config.Config{EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", Domain: "sandbox.example.com", HTTPClientTimeout: time.Second}
	svc.caddy = caddy.New(svc.cfg)
	svc.AttachCluster(&failingExposeCluster{Noop: cluster.NewNoop("node-1", "http://node-1", ""), addErr: errors.New("cluster write failed")})

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-http-replace", Image: "alpine:3.20", Status: models.SandboxStatusStarted, ContainerID: "ctr-http-replace", ContainerIP: "10.0.0.70", Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 256, DiskGB: 5, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{SandboxID: "sb-http-replace", Port: 8080, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://sb-http-replace-8080.sandbox.example.com", CreatedAt: now}); err != nil {
		t.Fatalf("UpsertPort() error = %v", err)
	}

	_, err := svc.ExposePort(ctx, "sb-http-replace", 8080, models.ExposedPortProtocolHTTP)
	if err == nil || !strings.Contains(err.Error(), "cluster: record exposed port") {
		t.Fatalf("ExposePort() error = %v, want cluster record failure", err)
	}
	got, err := st.Get(ctx, "sb-http-replace")
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	exposure := findExposure(got, 8080)
	if exposure == nil || exposure.Protocol != models.ExposedPortProtocolHTTP {
		t.Fatalf("http exposure after failed replace = %+v, want existing http row", exposure)
	}
	if !fake.hasHTTPRoute(caddy.PortRouteID("sb-http-replace", 8080)) {
		t.Fatal("HTTP route should remain installed on replacement failure")
	}
	if len(rt.pushes) != 0 {
		t.Fatalf("allowlist pushes = %d, want 0 on failed replacement", len(rt.pushes))
	}
}

func TestExposePortTCPReusedReservationKeepsRouteOnClusterFailure(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	fake := newRouteAdminCaddyFake()
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc.cfg = config.Config{EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", Domain: "sandbox.example.com", HTTPClientTimeout: time.Second}
	svc.caddy = caddy.New(svc.cfg)
	svc.l4Ready.Store(true)
	svc.AttachCluster(&failingExposeCluster{Noop: cluster.NewNoop("node-1", "http://node-1", ""), addErr: errors.New("cluster write failed")})

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-tcp-replace", Image: "postgres:16", Status: models.SandboxStatusStarted, ContainerID: "ctr-tcp-replace", ContainerIP: "10.0.0.71", Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 256, DiskGB: 5, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{SandboxID: "sb-tcp-replace", Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 32123, PublicURL: "tcp://sandbox.example.com:32123", CreatedAt: now}); err != nil {
		t.Fatalf("UpsertPort() error = %v", err)
	}

	_, err := svc.ExposePort(ctx, "sb-tcp-replace", 5432, models.ExposedPortProtocolTCP)
	if err == nil || !strings.Contains(err.Error(), "cluster: record exposed port") {
		t.Fatalf("ExposePort() error = %v, want cluster record failure", err)
	}
	got, err := st.Get(ctx, "sb-tcp-replace")
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	exposure := findExposure(got, 5432)
	if exposure == nil || exposure.Protocol != models.ExposedPortProtocolTCP || exposure.HostPort != 32123 {
		t.Fatalf("tcp exposure after failed replace = %+v, want existing tcp row", exposure)
	}
	if !fake.hasTCPServer(testTCPServerID(32123)) {
		t.Fatal("TCP server should remain installed on reused reservation failure")
	}
	if len(rt.pushes) != 0 {
		t.Fatalf("allowlist pushes = %d, want 0 on failed replacement", len(rt.pushes))
	}
}

func TestExposePortTCPRollsBackReservedRowOnCaddyFailure(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if (r.Method == http.MethodPut || r.Method == http.MethodPost) && strings.HasPrefix(r.URL.Path, "/config/apps/layer4/servers/tcp-port-") {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(server.Close)

	svc.cfg = config.Config{EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", Domain: "sandbox.example.com", L4PortRangeStart: 32000, L4PortRangeEnd: 32002, HTTPClientTimeout: time.Second}
	svc.caddy = caddy.New(svc.cfg)
	svc.l4Ready.Store(true)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-tcp-rollback", Image: "postgres:16", Status: models.SandboxStatusStarted, ContainerID: "ctr-tcp-rollback", ContainerIP: "10.0.0.72", Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 256, DiskGB: 5, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	_, err := svc.ExposePort(ctx, "sb-tcp-rollback", 5432, models.ExposedPortProtocolTCP)
	if err == nil || !strings.Contains(err.Error(), "upsert tcp server failed: 500") {
		t.Fatalf("ExposePort() error = %v, want caddy tcp failure", err)
	}
	got, err := st.Get(ctx, "sb-tcp-rollback")
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if exposure := findExposure(got, 5432); exposure != nil {
		t.Fatalf("tcp exposure after rollback = %+v, want none", exposure)
	}
}

func TestExposePortTLSRollsBackRouteOnStoreFailure(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, dbPath, rt)
	fake := newRouteAdminCaddyFake()
	fake.afterMutation = func(method, path, id string) {
		if method == http.MethodPut && path == "/config/apps/layer4/servers/tls-mux/routes/0" {
			_ = st.Close()
		}
	}
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc.cfg = config.Config{EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", Domain: "sandbox.example.com", L4TLSListen: ":443", HTTPClientTimeout: time.Second}
	svc.caddy = caddy.New(svc.cfg)
	svc.l4Ready.Store(true)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-tls-rollback", Image: "redis:7", Status: models.SandboxStatusStarted, ContainerID: "ctr-tls-rollback", ContainerIP: "10.0.0.73", Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 256, DiskGB: 5, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	_, err := svc.ExposePort(ctx, "sb-tls-rollback", 8443, models.ExposedPortProtocolTLS)
	if err == nil || !strings.Contains(err.Error(), "database is closed") {
		t.Fatalf("ExposePort() error = %v, want store failure after tls route upsert", err)
	}
	if fake.hasTLSRoute(testTLSRouteID("sb-tls-rollback", 8443)) {
		t.Fatal("TLS route should have been deleted during rollback")
	}
	reopened, err := storepkg.Open(dbPath)
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer reopened.Close()
	got, err := reopened.Get(ctx, "sb-tls-rollback")
	if err != nil {
		t.Fatalf("reopened store.Get() error = %v", err)
	}
	if exposure := findExposure(got, 8443); exposure != nil {
		t.Fatalf("tls exposure after rollback = %+v, want none", exposure)
	}
}

func TestUnexposePortReturnsDeleteRouteErrorAndKeepsExposure(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete && r.URL.Path == "/id/"+caddy.PortRouteID("sb-unexpose-route-fail", 8080) {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(server.Close)

	svc.cfg = config.Config{EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", Domain: "sandbox.example.com", HTTPClientTimeout: time.Second}
	svc.caddy = caddy.New(svc.cfg)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-unexpose-route-fail", Image: "alpine:3.20", Status: models.SandboxStatusStarted, ContainerID: "ctr-unexpose-route-fail", ContainerIP: "10.0.0.74", Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 256, DiskGB: 5, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
	if err := st.UpsertPort(ctx, models.ExposedPort{SandboxID: "sb-unexpose-route-fail", Port: 8080, Protocol: models.ExposedPortProtocolHTTP, PublicURL: "https://sb-unexpose-route-fail-8080.sandbox.example.com", CreatedAt: now}); err != nil {
		t.Fatalf("UpsertPort() error = %v", err)
	}

	err := svc.UnexposePort(ctx, "sb-unexpose-route-fail", 8080)
	if err == nil || !strings.Contains(err.Error(), "delete caddy route failed: 500") {
		t.Fatalf("UnexposePort() error = %v, want route delete failure", err)
	}
	got, err := st.Get(ctx, "sb-unexpose-route-fail")
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if exposure := findExposure(got, 8080); exposure == nil || exposure.Protocol != models.ExposedPortProtocolHTTP {
		t.Fatalf("http exposure after failed unexpose = %+v, want preserved row", exposure)
	}
}

func TestStartSandboxReturnsErrorWhenSandboxRouteUpsertFails(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{startState: &models.SandboxRuntimeState{SandboxID: "sb-start-sandbox-route-fail", ContainerID: "ctr-start-sandbox-route-new", ContainerIP: "10.0.0.75", Status: models.SandboxStatusStarted}}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPatch && r.URL.Path == "/id/"+caddy.SandboxRouteID("sb-start-sandbox-route-fail") {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(server.Close)

	svc.cfg = config.Config{Runtime: models.RuntimeDocker, ToolboxPort: 4321, EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", Domain: "sandbox.example.com", HTTPClientTimeout: time.Second}
	svc.caddy = caddy.New(svc.cfg)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-start-sandbox-route-fail", Image: "alpine:3.20", Status: models.SandboxStatusStopped, ContainerID: "ctr-start-sandbox-route-old", ContainerIP: "10.0.0.44", Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 256, DiskGB: 5, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	_, err := svc.StartSandbox(ctx, "sb-start-sandbox-route-fail")
	if err == nil || !strings.Contains(err.Error(), "patch caddy route failed: 500") {
		t.Fatalf("StartSandbox() error = %v, want sandbox-route caddy failure", err)
	}
	if len(rt.startRefs) != 1 || rt.startRefs[0] != "ctr-start-sandbox-route-old" {
		t.Fatalf("runtime Start refs = %v, want [ctr-start-sandbox-route-old]", rt.startRefs)
	}
	if len(rt.pushes) != 0 {
		t.Fatalf("allowlist pushes = %d, want none on failed restart", len(rt.pushes))
	}
	if cap := svc.Capacity(); cap.SandboxesActive != 1 || cap.ReservedCPU != 1 || cap.ReservedMemoryMB != 256 {
		t.Fatalf("capacity snapshot after sandbox-route failure = %+v, want running reservation kept", cap)
	}
	got, err := st.Get(ctx, "sb-start-sandbox-route-fail")
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if got.Status != models.SandboxStatusStopped || got.ContainerID != "ctr-start-sandbox-route-old" || got.ContainerIP != "10.0.0.44" {
		t.Fatalf("stored sandbox after failed restart = %+v, want original stopped row", got)
	}
}

func TestStartSandboxReturnsErrorWhenRefreshGetMissesAfterUpsert(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "state.db")
	rt := &recordingRuntime{startState: &models.SandboxRuntimeState{SandboxID: "sb-start-refresh-miss", ContainerID: "ctr-start-refresh-new", ContainerIP: "10.0.0.76", Status: models.SandboxStatusStarted}}
	svc, st, _ := newServiceRuntimeHarnessAtPath(t, dbPath, rt)
	fake := newRouteAdminCaddyFake()
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc.cfg = config.Config{Runtime: models.RuntimeDocker, ToolboxPort: 4321, EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", Domain: "sandbox.example.com", HTTPClientTimeout: time.Second}
	svc.caddy = caddy.New(svc.cfg)

	rawDB, err := sql.Open("sqlite3", sqliteDSNForTest(dbPath))
	if err != nil {
		t.Fatalf("sql.Open() error = %v", err)
	}
	defer rawDB.Close()
	if _, err := rawDB.Exec(`
		CREATE TRIGGER delete_started_after_restart
		AFTER UPDATE ON sandboxes
		WHEN NEW.id = 'sb-start-refresh-miss' AND NEW.status = 'started'
		BEGIN
			DELETE FROM sandboxes WHERE id = NEW.id;
		END;
	`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-start-refresh-miss", Image: "alpine:3.20", Status: models.SandboxStatusStopped, ContainerID: "ctr-start-refresh-old", ContainerIP: "10.0.0.45", Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 256, DiskGB: 5, CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	_, err = svc.StartSandbox(ctx, "sb-start-refresh-miss")
	if !errors.Is(err, storepkg.ErrNotFound) {
		t.Fatalf("StartSandbox() error = %v, want ErrNotFound after refresh get misses", err)
	}
	if len(rt.pushes) != 0 {
		t.Fatalf("allowlist pushes = %d, want none when refresh get fails", len(rt.pushes))
	}
	if !fake.hasHTTPRoute(caddy.SandboxRouteID("sb-start-refresh-miss")) {
		t.Fatal("sandbox route should remain installed before refresh get failure")
	}
}

func TestStartSandboxSucceedsWhenAllowedPortsSyncFails(t *testing.T) {
	ctx := context.Background()
	base := &recordingRuntime{startState: &models.SandboxRuntimeState{SandboxID: "sb-start-allowlist", ContainerID: "ctr-start-allowlist-new", ContainerIP: "10.0.0.77", Status: models.SandboxStatusStarted}}
	rt := &pushErrorRuntime{recordingRuntime: base, pushErr: errors.New("toolbox down")}
	svc, st, _ := newServiceRuntimeHarness(t, base)
	fake := newRouteAdminCaddyFake()
	server := httptest.NewServer(fake.handler(t))
	t.Cleanup(server.Close)

	svc.docker = rt
	svc.cfg = config.Config{Runtime: models.RuntimeDocker, ToolboxPort: 4321, EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", Domain: "sandbox.example.com", HTTPClientTimeout: time.Second}
	svc.caddy = caddy.New(svc.cfg)

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{ID: "sb-start-allowlist", Image: "alpine:3.20", Status: models.SandboxStatusStopped, ContainerID: "ctr-start-allowlist-old", ContainerIP: "10.0.0.46", Runtime: models.RuntimeDocker, CPU: 1, MemoryMB: 256, DiskGB: 5, ToolboxToken: "toolbox-token", CreatedAt: now, UpdatedAt: now, LastActiveAt: now}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	started, err := svc.StartSandbox(ctx, "sb-start-allowlist")
	if err != nil {
		t.Fatalf("StartSandbox() error = %v", err)
	}
	if started.Status != models.SandboxStatusStarted || started.ContainerID != "ctr-start-allowlist-new" || started.ContainerIP != "10.0.0.77" {
		t.Fatalf("returned sandbox = %+v, want refreshed started sandbox", started)
	}
	if len(rt.pushes) != 1 {
		t.Fatalf("push attempts = %d, want 1", len(rt.pushes))
	}
	if rt.pushes[0].containerIP != "10.0.0.77" || rt.pushes[0].token != "toolbox-token" {
		t.Fatalf("allowlist push = %+v, want refreshed container IP and token", rt.pushes[0])
	}
	got, err := st.Get(ctx, "sb-start-allowlist")
	if err != nil {
		t.Fatalf("store.Get() error = %v", err)
	}
	if got.Status != models.SandboxStatusStarted || got.ContainerID != "ctr-start-allowlist-new" || got.ContainerIP != "10.0.0.77" {
		t.Fatalf("stored sandbox = %+v, want persisted started row", got)
	}
}
