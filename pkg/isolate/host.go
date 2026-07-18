package isolate

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/jsbundle"
)

// HostConfig configures one workerd group host.
type HostConfig struct {
	// WorkerdPath is the workerd binary.
	WorkerdPath string
	// GroupKey is the isolate-group key (§2.1); also the workerLoader cache id.
	GroupKey string
	// RunDir is the group's private run directory (sockets + generated config).
	RunDir string
	// StartTimeout bounds the spawn→ready wait. Zero → 10s.
	StartTimeout time.Duration
}

// Host owns one workerd process for an isolate group and the Go-side
// bundle-server the controller fetches bundles from. It is safe for concurrent
// use: Load/Unload/Invoke may race with each other.
type Host struct {
	cfg HostConfig

	controlSock string
	hostSock    string
	egressSock  string

	mu           sync.RWMutex
	bundles      map[string]*jsbundle.Bundle // sandbox id → pinned bundle
	egressPolicy map[string]EgressPolicy     // sandbox id → outbound policy

	cmd        *exec.Cmd
	bundleSrv  *http.Server
	egressSrv  *http.Server
	ctrlClient *http.Client
	started    bool
}

// NewHost prepares (does not start) a group host.
func NewHost(cfg HostConfig) (*Host, error) {
	if strings.TrimSpace(cfg.WorkerdPath) == "" {
		return nil, fmt.Errorf("isolate: workerd path is required")
	}
	if err := validateLoaderID(cfg.GroupKey); err != nil {
		return nil, err
	}
	if strings.TrimSpace(cfg.RunDir) == "" {
		return nil, fmt.Errorf("isolate: run dir is required")
	}
	if cfg.StartTimeout == 0 {
		cfg.StartTimeout = 10 * time.Second
	}
	return &Host{
		cfg:          cfg,
		controlSock:  filepath.Join(cfg.RunDir, controlSocketName),
		hostSock:     filepath.Join(cfg.RunDir, hostSocketName),
		egressSock:   filepath.Join(cfg.RunDir, egressSocketName),
		bundles:      make(map[string]*jsbundle.Bundle),
		egressPolicy: make(map[string]EgressPolicy),
	}, nil
}

// Load pins a sandbox's bundle so the controller's provider can fetch it on the
// next request for that id. Idempotent: re-loading the same id replaces the
// pin. Loading does not itself spawn an isolate — the first Invoke does, on a
// loader cache miss.
func (h *Host) Load(id string, b *jsbundle.Bundle) error {
	if id == "" {
		return fmt.Errorf("isolate: empty sandbox id")
	}
	if err := b.Validate(); err != nil {
		return err
	}
	h.mu.Lock()
	h.bundles[id] = b
	h.mu.Unlock()
	return nil
}

// Unload drops a sandbox's bundle pin. A subsequent request for that id fails
// the provider's fetch (404) and the controller returns 502 — the sandbox is
// gone. Returns the number of bundles still pinned (the group's live-member
// count, for last-member teardown).
func (h *Host) Unload(id string) int {
	h.mu.Lock()
	delete(h.bundles, id)
	delete(h.egressPolicy, id)
	n := len(h.bundles)
	h.mu.Unlock()
	return n
}

// LoadedCount is the number of sandboxes currently pinned on this host.
func (h *Host) LoadedCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.bundles)
}

// Start generates the group's config + controller, starts the bundle-server and
// the Phase-3 attributed egress server on their unix sockets, spawns workerd,
// and waits until the control socket answers.
func (h *Host) Start(ctx context.Context) error {
	if err := os.MkdirAll(h.cfg.RunDir, 0o700); err != nil {
		return fmt.Errorf("isolate: mkdir run dir: %w", err)
	}
	// Stale sockets from a crashed predecessor would make workerd's bind fail.
	for _, s := range []string{h.controlSock, h.hostSock, h.egressSock} {
		_ = os.Remove(s)
	}

	if err := h.startBundleServer(); err != nil {
		return err
	}
	if err := h.startEgressServer(); err != nil {
		_ = h.stopServers()
		return err
	}

	if err := h.writeConfig(); err != nil {
		_ = h.stopServers()
		return err
	}

	configPath := filepath.Join(h.cfg.RunDir, "config.capnp")
	cmd := exec.Command(h.cfg.WorkerdPath, "serve", "--experimental", configPath)
	cmd.Dir = h.cfg.RunDir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		_ = h.stopServers()
		return fmt.Errorf("isolate: start workerd: %w", err)
	}
	h.cmd = cmd
	h.ctrlClient = unixHTTPClient(h.controlSock)

	if err := h.waitReady(ctx); err != nil {
		_ = h.Stop()
		return err
	}
	h.started = true
	return nil
}

func (h *Host) writeConfig() error {
	if err := os.WriteFile(filepath.Join(h.cfg.RunDir, controllerModuleName), []byte(controllerJS), 0o600); err != nil {
		return fmt.Errorf("isolate: write controller: %w", err)
	}
	cfg := capnpConfig(h.controlSock, h.hostSock, h.egressSock, h.cfg.GroupKey)
	if err := os.WriteFile(filepath.Join(h.cfg.RunDir, "config.capnp"), []byte(cfg), 0o600); err != nil {
		return fmt.Errorf("isolate: write config: %w", err)
	}
	return nil
}

// startBundleServer serves GET /bundle/<id> from the pinned-bundle map over the
// host unix socket. This is what the controller's provider fetches on a loader
// cache miss.
func (h *Host) startBundleServer() error {
	ln, err := net.Listen("unix", h.hostSock)
	if err != nil {
		return fmt.Errorf("isolate: listen bundle socket: %w", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/bundle/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/bundle/")
		h.mu.RLock()
		b := h.bundles[id]
		h.mu.RUnlock()
		if b == nil {
			http.Error(w, "no such sandbox", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(bundleWireJSON{
			CompatibilityDate: b.CompatibilityDate,
			MainModule:        b.MainModule,
			Modules:           b.Modules,
		})
	})
	h.bundleSrv = &http.Server{Handler: mux}
	go func() { _ = h.bundleSrv.Serve(ln) }()
	return nil
}

func (h *Host) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(h.cfg.StartTimeout)
	// A readiness probe carries a sentinel id the provider will 404 on; a 502
	// (load failed) still proves the controller is serving, which is all we
	// need to call the process ready.
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://ctrl/", nil)
		req.Header.Set("x-sb-id", "__readiness__")
		resp, err := h.ctrlClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		if h.cmd.ProcessState != nil && h.cmd.ProcessState.Exited() {
			return fmt.Errorf("isolate: workerd exited during startup")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return fmt.Errorf("isolate: workerd control socket not ready within %s", h.cfg.StartTimeout)
}

// Invoke proxies an HTTP request to the sandbox identified by id. The caller's
// request is forwarded verbatim except that x-sb-id is (re)set to id so the
// controller routes it; the isolate never sees the control header.
func (h *Host) Invoke(ctx context.Context, id string, r *http.Request) (*http.Response, error) {
	if !h.started {
		return nil, fmt.Errorf("isolate: host not started")
	}
	out := r.Clone(ctx)
	out.RequestURI = ""
	out.URL.Scheme = "http"
	out.URL.Host = "ctrl"
	out.Host = "ctrl"
	out.Header.Set("x-sb-id", id)
	return h.ctrlClient.Do(out)
}

// stopServers shuts down the bundle + egress servers and removes their sockets.
func (h *Host) stopServers() error {
	if h.bundleSrv != nil {
		_ = h.bundleSrv.Close()
	}
	if h.egressSrv != nil {
		_ = h.egressSrv.Close()
	}
	for _, s := range []string{h.hostSock, h.egressSock, h.controlSock} {
		_ = os.Remove(s)
	}
	return nil
}

// Stop kills the workerd process and tears down the host servers. Idempotent.
func (h *Host) Stop() error {
	h.started = false
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
		_, _ = h.cmd.Process.Wait()
		h.cmd = nil
	}
	return h.stopServers()
}

// unixHTTPClient returns an http.Client whose transport dials the given unix
// socket regardless of the request's host.
func unixHTTPClient(sock string) *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", sock)
			},
		},
	}
}
