package isolate

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/pkg/jsbundle"
)

// defaultEgressPoolSize is the per-group egress-slot pool size when unset (§4).
// It caps concurrently-egressing sandboxes in a group; block-all sandboxes cost
// no slot. Sized generously because sockets are cheap and only bound per active
// egress sandbox; operators tune it via SB_ISOLATE_EGRESS_POOL_SIZE.
const defaultEgressPoolSize = 64

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
	// Jail is the OS confinement for the workerd process. When Jail.Require is
	// true, Start applies it before exec and FAILS CLOSED if it cannot be
	// realized on this platform — the group never runs unconfined.
	Jail JailConfig
	// EgressPoolSize is the number of per-slot egress services pre-declared in
	// the group config (§4). Caps concurrently-egressing sandboxes; zero →
	// defaultEgressPoolSize.
	EgressPoolSize int
	// Logger records egress pool-exhaustion spill (no silent caps). Nil →
	// slog.Default().
	Logger *slog.Logger
}

// Host owns one workerd process for an isolate group and the Go-side
// bundle-server the controller fetches bundles from. It is safe for concurrent
// use: Load/Unload/Invoke may race with each other.
type Host struct {
	cfg    HostConfig
	logger *slog.Logger

	controlSock    string
	hostSock       string
	egressDenySock string
	egressSocks    []string // slot → per-slot egress UDS path (len == pool size)

	// started is the fast-path liveness flag Invoke checks; atomic so a
	// concurrent Stop (last-member teardown / idle reaper) racing an in-flight
	// Invoke is not a data race. The pointer/server fields it gates are read
	// under mu.
	started atomic.Bool

	mu           sync.RWMutex
	bundles      map[string]*jsbundle.Bundle // sandbox id → pinned bundle
	egressPolicy map[string]EgressPolicy     // sandbox id → outbound policy
	// Egress slot allocation (§4): a sandbox with a non-block-all policy is
	// assigned a slot; its dedicated egress listener (slotSrv[slot]) is bound
	// lazily on assignment and torn down on Unload. Attribution is the socket,
	// so idBySlot[slot] is the authoritative owner the slot handler enforces.
	slotByID map[string]int // sandbox id → assigned slot
	idBySlot []string       // slot → sandbox id ("" == free)
	slotSrv  []*http.Server // slot → lazily-started listener (nil == unbound)
	// jail is what applyJail realized for this process (nil when unjailed);
	// Stop tears it down after the process is gone. Set in Start under mu.
	jail *jailRealized
	// cmd/ctrlClient/servers are set once in Start and cleared in Stop; guarded
	// by mu because Invoke reads ctrlClient while Stop nils cmd concurrently.
	cmd           *exec.Cmd
	bundleSrv     *http.Server
	egressDenySrv *http.Server
	ctrlClient    *http.Client

	// egressObserver records host-mediated destinations (E3a). Guarded by mu.
	egressObserver EgressObserver
}

// SetEgressObserver installs (or clears) the async egress attribution callback.
func (h *Host) SetEgressObserver(obs EgressObserver) {
	if h == nil {
		return
	}
	h.mu.Lock()
	h.egressObserver = obs
	h.mu.Unlock()
}

func (h *Host) observeEgress(sandboxID, network, destination string) {
	if h == nil {
		return
	}
	h.mu.RLock()
	obs := h.egressObserver
	h.mu.RUnlock()
	if obs == nil {
		return
	}
	sid, netw, dest := sandboxID, network, destination
	go obs(sid, netw, dest)
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
	if cfg.Jail.Require && cfg.Jail.ChrootDir != "" {
		// Both sides must name the same inodes: workerd binds sockets at
		// /run/... inside its root, the Go side dials <chroot>/run/... on the
		// host. Anywhere else the jailed process could not reach them.
		want := filepath.Join(cfg.Jail.ChrootDir, JailRunDirName)
		if filepath.Clean(cfg.RunDir) != want {
			return nil, fmt.Errorf("isolate: jailed run dir must be %s (got %s)", want, cfg.RunDir)
		}
	}
	if cfg.StartTimeout == 0 {
		cfg.StartTimeout = 10 * time.Second
	}
	if cfg.EgressPoolSize <= 0 {
		cfg.EgressPoolSize = defaultEgressPoolSize
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	egressSocks := make([]string, cfg.EgressPoolSize)
	for i := range egressSocks {
		egressSocks[i] = filepath.Join(cfg.RunDir, egressSlotSocketName(i))
	}
	return &Host{
		cfg:            cfg,
		logger:         logger,
		controlSock:    filepath.Join(cfg.RunDir, controlSocketName),
		hostSock:       filepath.Join(cfg.RunDir, hostSocketName),
		egressDenySock: filepath.Join(cfg.RunDir, egressDenySocketName),
		egressSocks:    egressSocks,
		bundles:        make(map[string]*jsbundle.Bundle),
		egressPolicy:   make(map[string]EgressPolicy),
		slotByID:       make(map[string]int),
		idBySlot:       make([]string, cfg.EgressPoolSize),
		slotSrv:        make([]*http.Server, cfg.EgressPoolSize),
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
	if slot, ok := h.slotByID[id]; ok {
		h.freeSlotLocked(id, slot)
	}
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
	stale := append([]string{h.controlSock, h.hostSock, h.egressDenySock}, h.egressSocks...)
	for _, s := range stale {
		_ = os.Remove(s)
	}

	if err := h.startBundleServer(); err != nil {
		return err
	}
	// The deny service (EGRESS_DENY) is always up: block-all and pool-exhausted
	// sandboxes bind it. Per-slot egress listeners are bound lazily when the
	// driver assigns a slot (SetEgressPolicy), so an idle group holds none.
	if err := h.startEgressDenyServer(); err != nil {
		_ = h.stopServers()
		return err
	}

	if err := h.writeConfig(); err != nil {
		_ = h.stopServers()
		return err
	}

	configPath := filepath.Join(h.cfg.RunDir, "config.capnp")
	workerdArgs := []string{"serve", "--experimental", h.inJail(configPath)}
	cmd := exec.Command(h.cfg.WorkerdPath, workerdArgs...)
	cmd.Dir = h.cfg.RunDir
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	// Fail-closed jail gate: if confinement is REQUIRED but this platform can't
	// realize it (or the spec is incomplete), refuse to spawn rather than run
	// untrusted tenant JS unconfined while the operator believes it is jailed.
	var realized *jailRealized
	if h.cfg.Jail.Require {
		var err error
		realized, err = applyJail(cmd, h.cfg.Jail, workerdArgs)
		if err != nil {
			_ = h.stopServers()
			// MkdirAll(RunDir) may have created <chroot>/run before applyJail
			// refused (non-root, missing shim, …). Drop the group tree so a
			// failed required-jail start never leaves a half-built chroot.
			if dir := h.cfg.Jail.ChrootDir; dir != "" {
				_ = os.RemoveAll(dir)
			}
			return fmt.Errorf("isolate: jail required but not realized here — refusing to spawn workerd unconfined (set SB_ISOLATE_USE_JAIL=false to run without a jail, accepting the risk): %w", err)
		}
		if len(realized.unknownSyscalls) > 0 {
			h.logger.Info("isolate jail: allowlist names absent on this architecture (skipped)", "group", h.cfg.GroupKey, "syscalls", realized.unknownSyscalls)
		}
		// Everything workerd must read or bind was created by root; hand it
		// to the jail identity now that the run dir exists.
		if err := h.grantJailAccess(h.cfg.RunDir, configPath, filepath.Join(h.cfg.RunDir, controllerModuleName), h.hostSock, h.egressDenySock); err != nil {
			_ = realized.teardown()
			_ = h.stopServers()
			return err
		}
	}
	if err := cmd.Start(); err != nil {
		realized.closeFD()
		_ = realized.teardown()
		_ = h.stopServers()
		return fmt.Errorf("isolate: start workerd: %w", err)
	}
	realized.closeFD()
	client := unixHTTPClient(h.controlSock)
	h.mu.Lock()
	h.cmd = cmd
	h.jail = realized
	h.ctrlClient = client
	h.mu.Unlock()

	if err := h.waitReady(ctx, cmd, client); err != nil {
		_ = h.Stop()
		return err
	}
	h.started.Store(true)
	return nil
}

func (h *Host) writeConfig() error {
	if err := os.WriteFile(filepath.Join(h.cfg.RunDir, controllerModuleName), []byte(controllerJS), 0o600); err != nil {
		return fmt.Errorf("isolate: write controller: %w", err)
	}
	egress := make([]string, len(h.egressSocks))
	for i, s := range h.egressSocks {
		egress[i] = h.inJail(s)
	}
	cfg := capnpConfig(h.inJail(h.controlSock), h.inJail(h.hostSock), egress, h.inJail(h.egressDenySock), h.cfg.GroupKey)
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
		slot, hasSlot := h.slotByID[id]
		h.mu.RUnlock()
		if b == nil {
			http.Error(w, "no such sandbox", http.StatusNotFound)
			return
		}
		wire := bundleWireJSON{
			CompatibilityDate: b.CompatibilityDate,
			MainModule:        b.MainModule,
			Modules:           b.Modules,
		}
		// Carry the assigned egress slot so the controller binds this sandbox's
		// globalOutbound to its dedicated slot service; no slot → EGRESS_DENY.
		if hasSlot {
			s := slot
			wire.EgressSlot = &s
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wire)
	})
	h.bundleSrv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 << 10,
	}
	go func() { _ = h.bundleSrv.Serve(ln) }()
	return nil
}

// waitReady polls the control socket until the controller answers. cmd and
// client are passed in (not read from the struct) so this runs entirely on
// startup-local state — no lock needed and no race with a later Invoke/Stop.
func (h *Host) waitReady(ctx context.Context, cmd *exec.Cmd, client *http.Client) error {
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
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		if cmd.ProcessState != nil && cmd.ProcessState.Exited() {
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
	if !h.started.Load() {
		return nil, fmt.Errorf("isolate: host not started")
	}
	h.mu.RLock()
	client := h.ctrlClient
	h.mu.RUnlock()
	if client == nil {
		return nil, fmt.Errorf("isolate: host not started")
	}
	out := r.Clone(ctx)
	out.RequestURI = ""
	out.URL.Scheme = "http"
	out.URL.Host = "ctrl"
	out.Host = "ctrl"
	out.Header.Set("x-sb-id", id)
	return client.Do(out)
}

// stopServers shuts down the bundle + egress (deny + all per-slot) servers and
// removes their sockets.
func (h *Host) stopServers() error {
	h.mu.Lock()
	if h.bundleSrv != nil {
		_ = h.bundleSrv.Close()
	}
	if h.egressDenySrv != nil {
		_ = h.egressDenySrv.Close()
	}
	for i, srv := range h.slotSrv {
		if srv != nil {
			_ = srv.Close()
			h.slotSrv[i] = nil
		}
	}
	h.mu.Unlock()
	socks := append([]string{h.hostSock, h.egressDenySock, h.controlSock}, h.egressSocks...)
	for _, s := range socks {
		_ = os.Remove(s)
	}
	return nil
}

// Stop kills the workerd process and tears down the host servers. Idempotent.
func (h *Host) Stop() error {
	h.started.Store(false)
	h.mu.Lock()
	cmd := h.cmd
	jail := h.jail
	h.cmd = nil
	h.jail = nil
	h.mu.Unlock()
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}
	err := h.stopServers()
	if jail != nil {
		// After the process: the kernel refuses to remove a populated cgroup,
		// and the run dir inside the chroot holds the sockets we just closed.
		if terr := jail.teardown(); terr != nil && h.logger != nil {
			h.logger.Warn("isolate jail teardown incomplete", "group", h.cfg.GroupKey, "err", terr)
		}
	}
	return err
}

// ApplyCaps changes the group's cgroup caps while it runs: a warm blank host
// starts unlimited and takes the claiming tenant's caps here. No-op when the
// host is not jailed (there is no cgroup to write).
func (h *Host) ApplyCaps(cpu float64, memMB int) error {
	h.mu.RLock()
	jail := h.jail
	h.mu.RUnlock()
	return jail.applyCaps(cpu, memMB)
}

// inJail maps a host path under the chroot onto the path the jailed process
// sees. Unjailed hosts see the same paths on both sides.
func (h *Host) inJail(hostPath string) string {
	root := h.cfg.Jail.ChrootDir
	if !h.cfg.Jail.Require || root == "" {
		return hostPath
	}
	rel, err := filepath.Rel(root, hostPath)
	if err != nil || strings.HasPrefix(rel, "..") {
		return hostPath
	}
	return "/" + rel
}

// grantJailAccess hands root-created files to the jail identity. workerd
// must read its config and controller, and connect to (write) the sockets
// the Go side listens on; the run dir itself must be traversable and
// writable for the sockets workerd binds.
func (h *Host) grantJailAccess(paths ...string) error {
	if !h.cfg.Jail.Require {
		return nil
	}
	for _, p := range paths {
		if p == "" {
			continue
		}
		if _, err := os.Stat(p); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("isolate: jail access %s: %w", p, err)
		}
		if err := os.Chown(p, h.cfg.Jail.UID, h.cfg.Jail.GID); err != nil {
			return fmt.Errorf("isolate: chown %s to jail uid: %w", p, err)
		}
	}
	return nil
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
