package main

import (
	"crypto/subtle"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/podtrust"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

// Pod mode (plans/security-gaps-m1-m4.md §6.2, eng review D8). The sandbox
// is a Kubernetes pod whose spec is stored in etcd, so toolboxd boots with
// no token and no env. It starts parked: the toolbox API answers /health
// only, and the image's command waits. Its worker adopts it over an mTLS
// listener (podtrust) that admits only the worker its spec names, signed
// by the cell's worker CA: the adopt call carries the toolbox token and
// the env. Then the API serves with that token and the command starts.
//
// The spec gives toolboxd these, none of them secret:
//
//	SB_POD_MODE=1          turns pod mode on
//	SB_POD_WORKER          the node ID of the worker that made the pod
//	SB_POD_WORKER_CA       the worker CA's certificate file (PEM, a ConfigMap)
//	SB_POD_ADOPT_PORT      the mTLS listener's port (podtrust.DefaultAdoptPort)
//
// A pod-mode toolboxd that cannot load them exits at once: the pod fails
// and its create with it, rather than serving with no way to be adopted.

var podEnvKeys = []string{"SB_POD_MODE", "SB_POD_WORKER", "SB_POD_WORKER_CA", "SB_POD_ADOPT_PORT"}

// defaultWorkerCAPath is where the pod's spec mounts the worker CA.
const defaultWorkerCAPath = "/aerolvm/worker-ca/ca.crt"

type podModeConfig struct {
	worker string
	cas    *x509.CertPool
	port   int
	// sandboxID is the pod's own sandbox (SB_SANDBOX_ID); an adopt must
	// name it. Empty for a pod parked with no sandbox yet.
	sandboxID string
}

// loadPodMode reads the pod-mode settings: nil when pod mode is off.
func loadPodMode(getenv func(string) string, readFile func(string) ([]byte, error)) (*podModeConfig, error) {
	if strings.TrimSpace(getenv("SB_POD_MODE")) != "1" {
		return nil, nil
	}
	cfg := &podModeConfig{
		worker:    strings.TrimSpace(getenv("SB_POD_WORKER")),
		port:      podtrust.DefaultAdoptPort,
		sandboxID: strings.TrimSpace(getenv("SB_SANDBOX_ID")),
	}
	if cfg.worker == "" {
		return nil, errors.New("pod mode: SB_POD_WORKER (the worker's node ID) is required")
	}
	path := strings.TrimSpace(getenv("SB_POD_WORKER_CA"))
	if path == "" {
		path = defaultWorkerCAPath
	}
	pemBytes, err := readFile(path)
	if err != nil {
		return nil, fmt.Errorf("pod mode: worker CA %s: %w", path, err)
	}
	if cfg.cas, err = podtrust.LoadCAs(pemBytes); err != nil {
		return nil, fmt.Errorf("pod mode: worker CA %s: %w", path, err)
	}
	if p := strings.TrimSpace(getenv("SB_POD_ADOPT_PORT")); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("pod mode: SB_POD_ADOPT_PORT %q is not a port", p)
		}
		cfg.port = n
	}
	return cfg, nil
}

// loadPodModeFn is loadPodMode on the process; tests replace it.
var loadPodModeFn = func() (*podModeConfig, error) { return loadPodMode(os.Getenv, os.ReadFile) }

// scrubPodEnv keeps the pod-mode settings out of the sandbox's processes:
// they are AerolVM's, not the image's.
func scrubPodEnv() {
	for _, k := range podEnvKeys {
		_ = os.Unsetenv(k)
	}
}

var (
	errAdoptNoToken      = errors.New("adopt: a token is required")
	errAdoptOtherSandbox = errors.New("adopt: this pod belongs to another sandbox")
)

// maxAdoptBytes bounds an adopt call: env of a few hundred KB at most.
const maxAdoptBytes = 1 << 20

// podAdopter serves the adopt call. Its lock makes "is it adopted, by
// which token" and the adopt itself one step, so two adopts at once never
// both win.
type podAdopter struct {
	srv       *server
	logger    *slog.Logger
	sandboxID string
	// startCommand starts the held-back image command; once, on the first
	// adopt.
	startCommand func()
	mu           sync.Mutex
	started      sync.Once
}

func (a *podAdopter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != podtrust.AdoptPath {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "adopt: POST only", http.StatusMethodNotAllowed)
		return
	}
	var frame readyproto.AdoptFrame
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxAdoptBytes)).Decode(&frame); err != nil {
		http.Error(w, "adopt: the body is not an adopt frame", http.StatusBadRequest)
		return
	}
	ack, first, err := a.adopt(frame)
	switch {
	case errors.Is(err, errAdoptedElsewhere), errors.Is(err, errAdoptOtherSandbox):
		http.Error(w, err.Error(), http.StatusConflict)
		return
	case err != nil:
		// Never the env or the token: sandboxenv's errors name neither.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ack)
	if first {
		// After the answer, as the parked handshake starts it after its
		// ack: the env and the identity are in place already.
		a.started.Do(a.startCommand)
	}
}

// adopt applies frame: env, then identity (applyAdoptFrame). The first
// token sticks: the same token again (a retry, or a start sending the env
// again) applies the frame again; another token is refused and changes
// nothing. first reports whether this adopt is the one that bound it.
func (a *podAdopter) adopt(frame readyproto.AdoptFrame) (ack readyproto.ReadySignal, first bool, err error) {
	frame.Token = strings.TrimSpace(frame.Token)
	frame.SandboxID = strings.TrimSpace(frame.SandboxID)
	if frame.Token == "" {
		return ack, false, errAdoptNoToken
	}
	if a.sandboxID != "" && frame.SandboxID != a.sandboxID {
		return ack, false, errAdoptOtherSandbox
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	a.srv.mu.RLock()
	adopted, held := a.srv.adopted, a.srv.authToken
	a.srv.mu.RUnlock()
	if adopted && subtle.ConstantTimeCompare([]byte(held), []byte(frame.Token)) != 1 {
		return ack, false, errAdoptedElsewhere
	}
	ack, err = a.srv.applyAdoptFrame(frame)
	if err != nil {
		return ack, false, err
	}
	return ack, !adopted, nil
}

// startPodAdoptFn is startPodAdopt; tests replace it.
var startPodAdoptFn = startPodAdopt

// startPodAdopt opens the mTLS adopt listener and serves it in the
// background. It returns the address it listens on.
func startPodAdopt(logger *slog.Logger, srv *server, cfg *podModeConfig) (net.Addr, error) {
	tlsCfg, err := podtrust.ServerConfig(cfg.cas, cfg.worker)
	if err != nil {
		return nil, err
	}
	ln, err := netListenFn("tcp", fmt.Sprintf(":%d", cfg.port))
	if err != nil {
		return nil, fmt.Errorf("pod mode: adopt listener: %w", err)
	}
	adopter := &podAdopter{
		srv:       srv,
		logger:    logger,
		sandboxID: cfg.sandboxID,
		startCommand: func() {
			srv.mu.RLock()
			deferred := append([]string(nil), srv.deferredCmd...)
			srv.mu.RUnlock()
			if len(deferred) > 0 {
				startUserCommandFn(logger, deferred)
			}
		},
	}
	hs := &http.Server{
		Handler:           adopter,
		TLSConfig:         tlsCfg,
		ReadHeaderTimeout: 10 * time.Second,
		// A refused handshake is the listener doing its job, not news.
		ErrorLog: slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
	}
	go func() {
		if err := hs.ServeTLS(ln, "", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("pod mode: adopt listener stopped", "error", err)
		}
	}()
	logger.Info("pod mode: waiting to be adopted by the worker", "worker", cfg.worker, "port", cfg.port)
	return ln.Addr(), nil
}
