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
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/models"
)

type server struct {
	logger    *slog.Logger
	sandboxID string
	authToken string
	port      int
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{}))

	srv := &server{
		logger:    logger,
		sandboxID: readSandboxID(),
		authToken: strings.TrimSpace(os.Getenv("SB_TOOLBOX_TOKEN")),
		port:      envInt("SB_TOOLBOX_PORT", 2280),
	}

	addr := fmt.Sprintf(":%d", srv.port)
	httpServer := &http.Server{
		Addr:              addr,
		Handler:           srv.routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	logger.Info("toolboxd listening", "addr", addr, "sandbox_id", srv.sandboxID, "version", version.Version)
	if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("toolboxd failed", "error", err)
		os.Exit(1)
	}
}

func (s *server) routes() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = s.stripSandboxPrefix(r)

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
		case strings.HasPrefix(r.URL.Path, "/proxy/"):
			s.handleProxy(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/process/execute":
			if !s.requireAuth(w, r) {
				return
			}
			s.handleExec(w, r)
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
	hostname, err := os.Hostname()
	if err != nil {
		hostname = ""
	}
	return resolveSandboxID(os.Getenv("SB_SANDBOX_ID"), hostname)
}

func resolveSandboxID(envValue, hostname string) string {
	if value := strings.TrimSpace(envValue); value != "" {
		return value
	}
	return strings.TrimSpace(hostname)
}

func normalizeSandboxPath(path, sandboxID string) string {
	if path == "" {
		return "/"
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
	case strings.HasPrefix(path, "/process/"):
		return true
	case strings.HasPrefix(path, "/files/"):
		return true
	case strings.HasPrefix(path, "/proxy/"):
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

	stdoutBytes, _ := io.ReadAll(stdout)
	stderrBytes, _ := io.ReadAll(stderr)
	waitErr := cmd.Wait()

	result := models.ExecResult{
		Stdout:     string(stdoutBytes),
		Stderr:     string(stderrBytes),
		DurationMS: time.Since(start).Milliseconds(),
	}

	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			result.ExitCode = -1
			result.Stderr = strings.TrimSpace(result.Stderr + "\n" + waitErr.Error())
		}
	} else {
		result.ExitCode = 0
	}

	writeJSON(w, http.StatusOK, result)
}

func (s *server) handleUpload(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		writeError(w, http.StatusBadRequest, "invalid multipart form")
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
	if _, err := os.Stat("/bin/sh"); err == nil {
		return "/bin/sh", nil
	}
	path, err := exec.LookPath("sh")
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

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, models.ErrorResponse{Error: message})
}

func dialable(address string) bool {
	conn, err := net.DialTimeout("tcp", address, 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}
