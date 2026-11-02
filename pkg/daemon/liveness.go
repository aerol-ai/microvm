package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"
)

// The liveness socket answers one question for the install.sh watchdog
// (sandboxd-healthcheck): is this process still responsive? It is not
// /health. /health is readiness: it lists the store, pings the container
// engine and Caddy, and probes the SSH gateway, so a daemon that is merely
// busy can take longer than the watchdog's probe budget to answer it. On the
// bank flagship (2026-11-01) a list storm did exactly that, the watchdog
// restarted a node that was alive, and every request in flight on it was
// lost.
//
// So this listener shares nothing with the API: its own Unix socket and
// accept loop (an API backlog full of list requests does not delay it), no
// middleware, no authentication, no store, no lock. It answers from two
// atomics. It opens first thing in the boot, so a daemon that is still
// booting answers "booting" instead of "connection refused" — which the old
// probe read as dead, and restarted mid-boot.
//
// What it cannot see: a daemon whose Go runtime is healthy but whose API is
// wedged on a dependency. That is a readiness failure, which /health and the
// alerts report; restarting the process does not fix a wedged engine or
// disk and does cost every request in flight.

const (
	livenessPath = "/livez"

	livenessSocketDirMode fs.FileMode = 0o700
	livenessSocketMode    fs.FileMode = 0o600
)

// The daemon's phase, as /livez reports it. Booting is the zero value.
const (
	livenessPhaseBooting int32 = iota
	livenessPhaseServing
	livenessPhaseStopping
)

// livenessServer is the liveness listener. A nil *livenessServer is valid
// and does nothing, so Run needs no branches when it is off.
type livenessServer struct {
	started time.Time
	phase   atomic.Int32
	srv     *http.Server
	ln      net.Listener
	done    chan struct{}
}

// livenessAnswer is the /livez body. Phase is for a person reading the
// watchdog's journal; the watchdog itself only needs the 200.
type livenessAnswer struct {
	Status        string `json:"status"`
	Phase         string `json:"phase"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

func livenessPhaseName(phase int32) string {
	switch phase {
	case livenessPhaseServing:
		return "serving"
	case livenessPhaseStopping:
		return "stopping"
	default:
		return "booting"
	}
}

// startLiveness opens the liveness socket at path and serves it until stop.
// An empty path means off. A socket that cannot be opened is logged and
// skipped, never fatal: the watchdog falls back to /health, which is what
// every release before this one did.
func startLiveness(path string, logger *slog.Logger) *livenessServer {
	if path == "" {
		return nil
	}
	ln, err := listenLivenessSocket(path)
	if err != nil {
		if logger != nil {
			logger.Warn("liveness socket not opened; the watchdog falls back to /health", "path", path, "error", err)
		}
		return nil
	}
	l := &livenessServer{started: time.Now(), ln: ln, done: make(chan struct{})}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+livenessPath, l.serveLivez)
	l.srv = &http.Server{
		Handler: mux,
		// The watchdog's probe is one tiny request; a slow client here can
		// only be a bug, never something to wait on.
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		IdleTimeout:       30 * time.Second,
	}
	go func() {
		defer close(l.done)
		if err := l.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) && logger != nil {
			logger.Warn("liveness socket stopped", "path", path, "error", err)
		}
	}()
	if logger != nil {
		logger.Info("liveness socket listening", "path", path)
	}
	return l
}

func (l *livenessServer) serveLivez(w http.ResponseWriter, _ *http.Request) {
	body, _ := json.Marshal(livenessAnswer{
		Status:        "alive",
		Phase:         livenessPhaseName(l.phase.Load()),
		UptimeSeconds: int64(time.Since(l.started) / time.Second),
	})
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(body, '\n'))
}

// setPhase records how far the daemon has got: booting, serving, stopping.
func (l *livenessServer) setPhase(phase int32) {
	if l == nil {
		return
	}
	l.phase.Store(phase)
}

// stop closes the listener (which removes the socket file) and waits for
// the accept loop to return. It does not wait for a probe in progress: the
// process is on its way out.
func (l *livenessServer) stop() {
	if l == nil {
		return
	}
	_ = l.srv.Close()
	<-l.done
}

// listenLivenessSocket makes the socket's directory (root 0700, as the
// unit's ExecStartPre already does for /run/sandboxd) and the socket (0600),
// replacing a socket a previous run left behind: a run ended by SIGKILL
// never removes its own, and a Unix listen on a leftover path fails.
func listenLivenessSocket(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, livenessSocketDirMode); err != nil {
		return nil, err
	}
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	case info.Mode()&fs.ModeSocket == 0:
		// The path came from configuration: refuse, never delete, a file
		// that is not a socket.
		return nil, fmt.Errorf("%s exists and is not a socket", path)
	default:
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale %s: %w", path, err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, livenessSocketMode); err != nil {
		_ = ln.Close()
		return nil, err
	}
	return ln, nil
}

// bootStopped turns a boot that ended because the daemon was asked to stop
// into a clean exit. A stop that lands mid-boot cancels whatever step is
// running, and that step returns its own "context canceled" error; reported
// as a failure, it exits 1, systemd records the unit as failed, and the
// watchdog — which starts a failed unit again — would undo an operator's
// `systemctl stop`. On the bank flagship it was the watchdog's second
// restart, 70 ms into the boot, that cancelled the containerd netns seed:
// "seed containerd netns pool: ... context canceled".
//
// Only a cancel of the caller's context counts. A listener failure cancels
// Run's own child context, which is a real fault and still returns its
// error; so does a deadline on the caller's context, which bounds a boot
// rather than asking it to stop.
func bootStopped(stop context.Context, err error, logger *slog.Logger) error {
	if err == nil || stop == nil || !errors.Is(stop.Err(), context.Canceled) {
		return err
	}
	if logger != nil {
		logger.Info("sandboxd stopped during boot", "interrupted_step", err.Error())
	}
	return nil
}
