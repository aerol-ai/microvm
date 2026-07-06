package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/clonegen"
	"github.com/aerol-ai/microvm/pkg/models"
)

var userCommandPID int

var (
	hostnameFn = os.Hostname
	statFn     = os.Stat
	lookPathFn = exec.LookPath
)

type vsockServerAPI interface {
	Serve(context.Context) error
	Close() error
}

var (
	sessionsNewFn            = sessions.New
	startReaperFn            = startReaper
	startUserCommandFn       = startUserCommand
	forwardShutdownSignalsFn = forwardShutdownSignals
	serveHTTPFn              = func(srv *http.Server, ln net.Listener) error { return srv.Serve(ln) }
	netListenFn              = func(network, addr string) (net.Listener, error) { return net.Listen(network, addr) }
	newVsockServerFn         = func(port uint32, handler VsockHandler, logger *slog.Logger) (vsockServerAPI, error) {
		return newVsockServer(port, handler, logger)
	}
)

type server struct {
	logger    *slog.Logger
	sandboxID string
	authToken string
	port      int

	mu           sync.RWMutex
	allowedPorts map[int]struct{}

	parkedMode  bool
	adopted     bool
	deferredCmd []string

	sessions *sessions.Manager
	daytona  *daytonaCompat
	envd     *envdCompat
	cloneGen *clonegen.Generation
}

func (s *server) servingRequests() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return !s.parkedMode || s.adopted
}

func (s *server) adoptIdentity(sandboxID, token string) {
	s.mu.Lock()
	s.sandboxID = strings.TrimSpace(sandboxID)
	s.authToken = strings.TrimSpace(token)
	s.adopted = true
	s.mu.Unlock()
}

func (s *server) setAllowedPorts(ports []int) {
	next := make(map[int]struct{}, len(ports))
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			next[p] = struct{}{}
		}
	}
	s.mu.Lock()
	s.allowedPorts = next
	s.mu.Unlock()
}

func (s *server) portAllowed(port int) bool {
	s.mu.RLock()
	_, ok := s.allowedPorts[port]
	s.mu.RUnlock()
	return ok
}

func main() {
	// --version / -v must be handled before any server setup so deploy
	// tooling (Ansible's update-toolboxd.yml) can probe an installed binary
	// without accidentally launching it as a daemon. Note: when toolboxd
	// runs inside a sandbox container, os.Args[1:] is the user's entry-point
	// command — there's no ambiguity here because a user command starting
	// with "--version" isn't a sensible sandbox entrypoint, and treating it
	// as a flag means we exit before binding the listener.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-v", "version":
			fmt.Println(version.Version)
			return
		}
	}

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))

	srv := &server{
		logger:       logger,
		sandboxID:    readSandboxID(),
		authToken:    strings.TrimSpace(os.Getenv("SB_TOOLBOX_TOKEN")),
		port:         envInt("SB_TOOLBOX_PORT", 2280),
		allowedPorts: map[int]struct{}{},
		parkedMode:   strings.TrimSpace(os.Getenv("SB_POOL_PARKED")) == "1",
		daytona:      newDaytonaCompat(),
		envd:         newEnvdCompat(),
		cloneGen:     clonegen.New(envString("SB_CLONE_GEN_PATH", clonegen.DefaultPath), logger),
	}
	readySocket := strings.TrimSpace(os.Getenv("SB_READY_SOCKET"))
	readyNonce := strings.TrimSpace(os.Getenv("SB_READY_NONCE"))
	bootstrapToken := srv.authToken
	// Evict the token from the process env table so child processes spawned
	// for the user command and /exec endpoints don't inherit it via os.Environ().
	os.Unsetenv("SB_TOOLBOX_TOKEN")
	scrubReadyEnv()

	startReaperFn(logger)

	sessionsMgr, err := sessionsNewFn(logger, sessions.Config{
		SandboxID:          srv.sandboxID,
		RecordingDir:       envString("SB_RECORDING_DIR", "/var/lib/toolboxd/recordings"),
		RecordingRetention: envDuration("SB_RECORDING_RETENTION", 7*24*time.Hour),
		BufferBytes:        envInt("SB_SESSION_BUFFER_BYTES", 1<<20),
	})
	if err != nil {
		logger.Warn("session manager init failed; sessions disabled", "error", err)
	} else {
		srv.sessions = sessionsMgr
		defer sessionsMgr.Close()
	}

	if len(os.Args) > 1 {
		if srv.parkedMode {
			srv.deferredCmd = append([]string{}, os.Args[1:]...)
		} else {
			startUserCommandFn(logger, os.Args[1:])
		}
	}

	addr := fmt.Sprintf(":%d", srv.port)
	httpServer := &http.Server{
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ln, err := netListenFn("tcp", addr)
	if err != nil {
		logger.Error("toolboxd listen failed", "error", err)
		os.Exit(1)
	}

	// Push readiness only after the HTTP listener is accepting — same contract
	// as /health 200 when create returns started.
	if srv.parkedMode {
		go runParkedReadyHandshake(logger, srv, readySocket, bootstrapToken, readyNonce)
	} else {
		announceReady(logger, srv.sandboxID, srv.authToken, readyNonce, readySocket)
	}

	go forwardShutdownSignalsFn(logger, httpServer)

	// Start the vsock listener alongside HTTP. On Linux guests with a
	// virtio-vsock device this binds (CID 3, port 1024) and accepts
	// control-plane signals from the host (pre-snapshot / post-resume).
	// On any other OS, or on a Linux host without AF_VSOCK support, the
	// listener constructor returns an error — we log it at WARN and keep
	// HTTP running. Vsock is additive; its absence does not block sandbox
	// operation, only the snapshot lifecycle hooks.
	//
	// Pass srv.sessions (may be nil if the manager failed to init above)
	// so the handler's pre_snapshot can fsync session recordings; nil
	// is treated as "no sessions to flush" by the handler.
	vsockHandler := newQuiesceHandler(logger, newSessionFlusher(srv.sessions), srv.cloneGen)
	if vs, err := newVsockServerFn(defaultVsockPort, vsockHandler, logger); err != nil {
		logger.Warn("vsock listener disabled", "error", err)
	} else {
		go func() {
			if err := vs.Serve(context.Background()); err != nil {
				logger.Warn("vsock serve exited", "error", err)
			}
		}()
		defer vs.Close()
	}

	logger.Info("toolboxd listening", "addr", addr, "sandbox_id", srv.sandboxID, "version", version.Version)
	if err := serveHTTPFn(httpServer, ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("toolboxd failed", "error", err)
		os.Exit(1)
	}
}

// sessionFlusherAdapter narrows *sessions.Manager down to the
// sessionFlusher interface the vsock quiesce handler expects. Nil
// manager → nil adapter (and the handler treats nil as "no sessions
// to flush"). Putting the adapter in main.go keeps the toolboxd
// cross-platform vsock.go file free of any sessions-package import,
// which matters because vsock.go is built on darwin too.
type sessionFlusherAdapter struct {
	mgr *sessions.Manager
}

func newSessionFlusher(mgr *sessions.Manager) sessionFlusher {
	if mgr == nil {
		return nil
	}
	return &sessionFlusherAdapter{mgr: mgr}
}

func (a *sessionFlusherAdapter) ListIDs() []string {
	ms := a.mgr.List()
	ids := make([]string, 0, len(ms))
	for _, s := range ms {
		ids = append(ids, s.ID)
	}
	return ids
}

func (a *sessionFlusherAdapter) FlushRecording(id string) error {
	return a.mgr.FlushRecording(id)
}

func startUserCommand(logger *slog.Logger, args []string) {
	cmd := exec.Command(args[0], args[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		logger.Error("failed to start user command", "args", args, "error", err)
		return
	}
	userCommandPID = cmd.Process.Pid
	if err := cmd.Process.Release(); err != nil {
		logger.Warn("failed to release user command handle", "error", err)
	}
	logger.Info("user command started", "pid", userCommandPID, "args", args)
}

// forwardShutdownSignals catches SIGTERM/SIGINT (sent by `docker stop` to PID 1)
// and propagates them to the user command's process group, then shuts the
// HTTP server down. Without this, the user command gets SIGKILLed after the
// docker stop grace period with no chance to clean up.
func forwardShutdownSignals(logger *slog.Logger, srv *http.Server) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT)
	sig := <-sigs
	logger.Info("toolboxd received shutdown signal", "signal", sig.String())

	if userCommandPID > 0 {
		// Negative PID targets the process group, so children of the user
		// command also receive the signal.
		if err := syscall.Kill(-userCommandPID, sig.(syscall.Signal)); err != nil {
			logger.Warn("failed to forward signal to user command", "error", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Warn("http shutdown error", "error", err)
	}
}

func startReaper(logger *slog.Logger) {
	sigs := make(chan os.Signal, 16)
	signal.Notify(sigs, syscall.SIGCHLD)
	go func() {
		for range sigs {
			for {
				var status syscall.WaitStatus
				pid, err := syscall.Wait4(-1, &status, syscall.WNOHANG, nil)
				if pid <= 0 || err != nil {
					break
				}
				switch {
				case pid == userCommandPID && status.Exited():
					logger.Info("user command exited", "pid", pid, "code", status.ExitStatus())
				case pid == userCommandPID && status.Signaled():
					logger.Info("user command killed", "pid", pid, "signal", status.Signal())
				default:
					logger.Debug("reaped orphan", "pid", pid)
				}
			}
		}
	}()
}

func (s *server) routes() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = s.stripSandboxPrefix(r)

		if !s.servingRequests() && r.URL.Path != "/health" {
			writeError(w, http.StatusServiceUnavailable, "sandbox not adopted")
			return
		}

		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/":
			writeJSON(w, http.StatusOK, map[string]any{
				"sandbox_id": s.sandboxID,
				"version":    version.Version,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "version": version.Version})
		case r.Method == http.MethodGet && r.URL.Path == "/version":
			writeJSON(w, http.StatusOK, map[string]any{"version": version.Version})
		case r.Method == http.MethodGet && r.URL.Path == "/clone-generation":
			// Unauthenticated like /health: the token is a non-sensitive
			// change-detector for snapshot clones, and external access is
			// gated by the auth'd v1 toolbox proxy. In-guest readers can use
			// this or the well-known file written by cloneGeneration.
			token, resumedAt := s.cloneGen.Current()
			writeJSON(w, http.StatusOK, map[string]any{"generation": token, "resumed_at": resumedAt})
		case strings.HasPrefix(r.URL.Path, "/proxy/"):
			s.handleProxy(w, r)
		case strings.HasPrefix(r.URL.Path, "/envd/"):
			if !s.requireAuth(w, r) {
				return
			}
			if !s.handleEnvdRoute(w, r) {
				writeEnvdError(w, http.StatusNotFound, "not found")
			}
		case r.Method == http.MethodPost && r.URL.Path == "/process/execute":
			if !s.requireAuth(w, r) {
				return
			}
			s.handleExec(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/process/code-run":
			if !s.requireAuth(w, r) {
				return
			}
			s.handleDaytonaCodeRun(w, r)
		case strings.HasPrefix(r.URL.Path, "/process/interpreter/"):
			// codeInterpreter.runCode() is Daytona's stateful Jupyter-kernel API.
			// We don't host a kernel in the default toolbox image; without an
			// explicit 501 here a WS upgrade GET would 404 with the default
			// branch's "not found" body, which the SDK can't disambiguate from
			// other "thing missing" failures. Hand back a clear 501.
			if !s.requireAuth(w, r) {
				return
			}
			writeError(w, http.StatusNotImplemented, "codeInterpreter is not implemented; use process.codeRun or process.executeCommand instead")
		case strings.HasPrefix(r.URL.Path, "/process/session"):
			if !s.requireAuth(w, r) {
				return
			}
			if !s.handleDaytonaProcessRoute(w, r) {
				writeError(w, http.StatusNotFound, "not found")
			}
		case r.Method == http.MethodPost && r.URL.Path == "/files/upload":
			if !s.requireAuth(w, r) {
				return
			}
			s.handleUpload(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/files/download":
			if !s.requireAuth(w, r) {
				return
			}
			s.handleDownload(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/files":
			if !s.requireAuth(w, r) {
				return
			}
			s.handleDaytonaListFiles(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/files/info":
			if !s.requireAuth(w, r) {
				return
			}
			s.handleDaytonaFileInfo(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/files/move":
			if !s.requireAuth(w, r) {
				return
			}
			s.handleDaytonaMoveFile(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/files/search":
			if !s.requireAuth(w, r) {
				return
			}
			s.handleDaytonaSearchFiles(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/files/find":
			if !s.requireAuth(w, r) {
				return
			}
			s.handleDaytonaFindInFiles(w, r)
		case strings.HasPrefix(r.URL.Path, "/git/"):
			if !s.requireAuth(w, r) {
				return
			}
			if !s.handleDaytonaGitRoute(w, r) {
				writeError(w, http.StatusNotFound, "not found")
			}
		case r.Method == http.MethodPost && r.URL.Path == "/admin/allowed-ports":
			if !s.requireAuth(w, r) {
				return
			}
			s.handleSetAllowedPorts(w, r)
		case r.Method == http.MethodGet && r.URL.Path == "/process/exec/stream":
			if !s.requireAuth(w, r) {
				return
			}
			s.handleExecStream(w, r)
		case strings.HasPrefix(r.URL.Path, "/sessions"):
			if !s.requireAuth(w, r) {
				return
			}
			if !s.handleSessionsRoute(w, r) {
				writeError(w, http.StatusNotFound, "not found")
			}
		default:
			writeError(w, http.StatusNotFound, "not found")
		}
	})
}

func (s *server) stripSandboxPrefix(r *http.Request) *http.Request {
	r.URL.Path = normalizeSandboxPath(r.URL.Path, s.sandboxID)
	return r
}

func readSandboxID() string {
	if id := strings.TrimSpace(os.Getenv("SB_SANDBOX_ID")); id != "" {
		return id
	}
	hostname, err := hostnameFn()
	if err != nil {
		return ""
	}
	return normalizeSandboxID(hostname)
}

func normalizeSandboxID(hostname string) string {
	return strings.TrimSpace(hostname)
}

func normalizeSandboxPath(path, sandboxID string) string {
	if path == "" {
		return "/"
	}
	if path == envdPrefix || strings.HasPrefix(path, envdPrefix+"/") {
		return path
	}

	if sandboxID != "" {
		prefix := "/" + sandboxID
		if path == prefix || path == prefix+"/" {
			return "/"
		}
		if strings.HasPrefix(path, prefix+"/") {
			trimmed := strings.TrimPrefix(path, prefix)
			if trimmed == "" {
				return "/"
			}
			return trimmed
		}
	}

	trimmed := strings.TrimPrefix(path, "/")
	if trimmed == "" {
		return "/"
	}

	first, rest, found := strings.Cut(trimmed, "/")
	if !found {
		if isKnownToolboxPath("/" + first) {
			return "/" + first
		}
		return "/"
	}

	if first == "" {
		return path
	}

	candidate := "/" + rest
	if isKnownToolboxPath(candidate) {
		return candidate
	}

	return path
}

func isKnownToolboxPath(path string) bool {
	switch {
	case path == "/":
		return true
	case path == "/health":
		return true
	case path == "/version":
		return true
	case path == "/clone-generation":
		return true
	case strings.HasPrefix(path, "/process/"):
		return true
	case path == "/files":
		return true
	case strings.HasPrefix(path, "/files/"):
		return true
	case strings.HasPrefix(path, "/git/"):
		return true
	case strings.HasPrefix(path, "/proxy/"):
		return true
	case strings.HasPrefix(path, "/envd/"):
		return true
	case path == "/sessions" || strings.HasPrefix(path, "/sessions/"):
		return true
	default:
		return false
	}
}

func (s *server) requireAuth(w http.ResponseWriter, r *http.Request) bool {
	if s.authToken == "" {
		return true
	}
	const prefix = "Bearer "
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, prefix) || strings.TrimPrefix(authorization, prefix) != s.authToken {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return false
	}
	return true
}

func (s *server) handleExec(w http.ResponseWriter, r *http.Request) {
	var req models.ExecRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if strings.TrimSpace(req.Command) == "" {
		writeError(w, http.StatusBadRequest, "command is required")
		return
	}

	timeout := time.Duration(req.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	shell, err := detectShell()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	start := time.Now()
	cmd := exec.CommandContext(ctx, shell, "-lc", req.Command)
	cmd.Env = append(os.Environ(), envMapToSlice(req.Env)...)
	if req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := cmd.Start(); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	var stdoutBytes []byte
	var stderrBytes []byte
	var readWG sync.WaitGroup
	readWG.Add(2)
	go func() {
		defer readWG.Done()
		stdoutBytes, _ = io.ReadAll(stdout)
	}()
	go func() {
		defer readWG.Done()
		stderrBytes, _ = io.ReadAll(stderr)
	}()
	readWG.Wait()
	waitErr := cmd.Wait()

	result := models.ExecResult{
		Stdout:     string(stdoutBytes),
		Stderr:     string(stderrBytes),
		DurationMS: time.Since(start).Milliseconds(),
	}

	result.ExitCode, _ = interpretWaitResult(waitErr)
	if waitErr != nil {
		var exitErr *exec.ExitError
		if !errors.As(waitErr, &exitErr) && !errors.Is(waitErr, syscall.ECHILD) {
			result.Stderr = strings.TrimSpace(result.Stderr + "\n" + waitErr.Error())
		}
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *server) handleUpload(w http.ResponseWriter, r *http.Request) {
	maxBytes := envInt64("SB_UPLOAD_MAX_BYTES", 256*1024*1024)
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form (or too large)")
		return
	}

	targetPath := strings.TrimSpace(r.FormValue("path"))
	if targetPath == "" {
		targetPath = strings.TrimSpace(r.URL.Query().Get("path"))
	}
	if targetPath == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "file is required")
		return
	}
	defer file.Close()

	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if err := writeMultipartFile(targetPath, file); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"path": targetPath,
		"name": header.Filename,
	})
}

func (s *server) handleDownload(w http.ResponseWriter, r *http.Request) {
	targetPath := strings.TrimSpace(r.URL.Query().Get("path"))
	if targetPath == "" {
		writeError(w, http.StatusBadRequest, "path is required")
		return
	}

	data, err := os.ReadFile(targetPath)
	if err != nil {
		status := http.StatusInternalServerError
		if errors.Is(err, os.ErrNotExist) {
			status = http.StatusNotFound
		}
		writeError(w, status, err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(targetPath)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *server) handleSetAllowedPorts(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Ports []int `json:"ports"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	s.setAllowedPorts(body.Ports)
	s.logger.Info("allowed ports updated", "ports", body.Ports)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "ports": body.Ports})
}

func (s *server) handleProxy(w http.ResponseWriter, r *http.Request) {
	segments := strings.Split(strings.TrimPrefix(r.URL.Path, "/proxy/"), "/")
	if len(segments) == 0 || strings.TrimSpace(segments[0]) == "" {
		writeError(w, http.StatusBadRequest, "port is required")
		return
	}

	port, err := strconv.Atoi(segments[0])
	if err != nil || port <= 0 || port > 65535 {
		writeError(w, http.StatusBadRequest, "invalid port")
		return
	}

	if !s.portAllowed(port) {
		writeError(w, http.StatusForbidden, "port not exposed")
		return
	}

	target, err := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", port))
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	rest := "/"
	if len(segments) > 1 {
		rest = "/" + strings.Join(segments[1:], "/")
	}

	proxy := httputil.NewSingleHostReverseProxy(target)
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.URL.Path = rest
		req.Host = target.Host
	}
	proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		writeError(w, http.StatusBadGateway, err.Error())
	}
	proxy.ServeHTTP(w, r)
}

func detectShell() (string, error) {
	if _, err := statFn("/bin/sh"); err == nil {
		return "/bin/sh", nil
	}
	path, err := lookPathFn("sh")
	if err == nil {
		return path, nil
	}
	return "", errors.New("no shell found in container")
}

func envMapToSlice(values map[string]string) []string {
	if len(values) == 0 {
		return nil
	}

	result := make([]string, 0, len(values))
	for key, value := range values {
		result = append(result, key+"="+value)
	}
	return result
}

func writeMultipartFile(path string, file multipart.File) error {
	tmp, err := os.Create(path)
	if err != nil {
		return err
	}
	defer tmp.Close()
	_, err = io.Copy(tmp, file)
	return err
}

func envInt(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt64(key string, fallback int64) int64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fallback
	}
	return parsed
}

func envString(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func envDuration(key string, fallback time.Duration) time.Duration {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, models.ErrorResponse{Error: message})
}
