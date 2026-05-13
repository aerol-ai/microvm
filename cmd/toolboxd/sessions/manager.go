package sessions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/creack/pty"
)

// Config controls Manager behavior. Defaults are sensible for an in-container
// daemon; everything is overridable via toolboxd env vars.
type Config struct {
	// SandboxID is recorded in metadata and used as a recordings subdirectory.
	SandboxID string
	// RecordingDir is where asciinema cast files land. Required.
	RecordingDir string
	// RecordingRetention prunes cast files older than this. Zero = never.
	RecordingRetention time.Duration
	// SweepInterval drives the retention sweeper. Default 1 h.
	SweepInterval time.Duration
	// BufferBytes is the per-session replay buffer size. Default 1 MiB.
	BufferBytes int
}

// Manager owns every Session running in the container.
type Manager struct {
	logger *slog.Logger
	cfg    Config

	mu     sync.Mutex
	byID   map[string]*Session // primary key
	byName map[string]*Session // running, named-keyed; entry removed when session exits

	closeCh chan struct{}
}

// New constructs a Manager and starts its retention sweeper.
func New(logger *slog.Logger, cfg Config) (*Manager, error) {
	if logger == nil {
		return nil, errors.New("logger is required")
	}
	if cfg.RecordingDir == "" {
		return nil, errors.New("RecordingDir is required")
	}
	if cfg.BufferBytes <= 0 {
		cfg.BufferBytes = 1 << 20
	}
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = time.Hour
	}
	if !filepath.IsAbs(cfg.RecordingDir) {
		return nil, fmt.Errorf("RecordingDir must be absolute: %q", cfg.RecordingDir)
	}
	if err := os.MkdirAll(filepath.Join(cfg.RecordingDir, cfg.SandboxID), 0o700); err != nil {
		return nil, fmt.Errorf("create recording dir: %w", err)
	}

	m := &Manager{
		logger:  logger,
		cfg:     cfg,
		byID:    map[string]*Session{},
		byName:  map[string]*Session{},
		closeCh: make(chan struct{}),
	}
	go m.runSweeper()
	return m, nil
}

// Close kills every running session and stops the sweeper. Best-effort.
func (m *Manager) Close() {
	select {
	case <-m.closeCh:
	default:
		close(m.closeCh)
	}
	m.mu.Lock()
	sessions := make([]*Session, 0, len(m.byID))
	for _, s := range m.byID {
		sessions = append(sessions, s)
	}
	m.mu.Unlock()
	for _, s := range sessions {
		s.shutdown()
	}
}

// List returns metadata for every session currently tracked, ordered by
// CreatedAt ascending.
func (m *Manager) List() []models.Session {
	m.mu.Lock()
	out := make([]models.Session, 0, len(m.byID))
	for _, s := range m.byID {
		out = append(out, s.Snapshot())
	}
	m.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// Get fetches a session by ID. Returns ErrNotFound if missing.
func (m *Manager) Get(id string) (*Session, error) {
	m.mu.Lock()
	s := m.byID[id]
	m.mu.Unlock()
	if s == nil {
		return nil, ErrNotFound
	}
	return s, nil
}

// GetByName fetches a running session by its stable name. Exited sessions are
// not returned because the byName map is cleared when a session finishes.
func (m *Manager) GetByName(name string) (*Session, error) {
	trimmed := strings.TrimSpace(name)
	m.mu.Lock()
	s := m.byName[trimmed]
	m.mu.Unlock()
	if s == nil {
		return nil, ErrNotFound
	}
	return s, nil
}

// GetOrCreate returns the running session with the given Name (creating it
// from req if absent). Used by SSH attach so `ssh sandbox+default@host`
// idempotently lands on a single shared shell.
func (m *Manager) GetOrCreate(ctx context.Context, req models.CreateSessionRequest) (*Session, bool, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		return nil, false, errors.New("name is required for GetOrCreate")
	}

	m.mu.Lock()
	if existing, ok := m.byName[name]; ok && !existing.exited.Load() {
		m.mu.Unlock()
		return existing, false, nil
	}
	m.mu.Unlock()

	created, err := m.Create(ctx, req)
	if err != nil {
		return nil, false, err
	}
	return created, true, nil
}

// Create starts a new session. Always assigns a fresh ID.
func (m *Manager) Create(ctx context.Context, req models.CreateSessionRequest) (*Session, error) {
	argv, err := buildArgv(req)
	if err != nil {
		return nil, err
	}
	id, err := newSessionID()
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "default"
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	if req.WorkDir != "" {
		cmd.Dir = req.WorkDir
	}
	cmd.Env = mergeEnv(req.Env)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setsid:  req.PTY,
		Setpgid: !req.PTY,
	}

	s := &Session{
		id:        id,
		name:      name,
		argv:      argv,
		workdir:   req.WorkDir,
		pty:       req.PTY,
		cols:      orDefault(req.Cols, 80),
		rows:      orDefault(req.Rows, 24),
		createdAt: time.Now().UTC(),
		buf:       newRing(m.cfg.BufferBytes),
		doneCh:    make(chan struct{}),
		cmd:       cmd,
	}

	// Recording is always-on; retention prunes old casts.
	rec, err := newRecorder(
		recordingPathForID(m.cfg.RecordingDir, m.cfg.SandboxID, id),
		s.cols, s.rows,
		fmt.Sprintf("%s — %s", name, strings.Join(argv, " ")),
	)
	if err != nil {
		m.logger.Warn("recorder init failed; continuing without recording", "session_id", id, "error", err)
	} else {
		s.recorder = rec
	}

	if req.PTY {
		ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: uint16(s.cols), Rows: uint16(s.rows)})
		if err != nil {
			s.failed = true
			_ = s.recorder.Close()
			return nil, fmt.Errorf("start pty: %w", err)
		}
		s.ptmx = ptmx
		s.startedAt = time.Now().UTC()
		s.pumpWG.Add(1)
		go s.runPump(ptmx, StreamStdout)
	} else {
		stdin, err := cmd.StdinPipe()
		if err != nil {
			return nil, fmt.Errorf("stdin pipe: %w", err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			_ = stdin.Close()
			return nil, fmt.Errorf("stdout pipe: %w", err)
		}
		stderr, err := cmd.StderrPipe()
		if err != nil {
			_ = stdin.Close()
			return nil, fmt.Errorf("stderr pipe: %w", err)
		}
		if err := cmd.Start(); err != nil {
			_ = stdin.Close()
			s.failed = true
			_ = s.recorder.Close()
			return nil, fmt.Errorf("start: %w", err)
		}
		s.stdin = stdin
		s.startedAt = time.Now().UTC()
		s.pumpWG.Add(2)
		go s.runPump(stdout, StreamStdout)
		go s.runPump(stderr, StreamStderr)
	}

	m.mu.Lock()
	m.byID[id] = s
	m.byName[name] = s
	m.mu.Unlock()

	go func() {
		s.waitAndFinish()
		// Drop the byName entry so a future GetOrCreate(name) starts a fresh
		// session rather than returning the dead one.
		m.mu.Lock()
		if m.byName[name] == s {
			delete(m.byName, name)
		}
		m.mu.Unlock()
		m.logger.Info("session ended",
			"session_id", id,
			"name", name,
			"exit_code", s.exitCode,
			"signal", s.exitSignal,
		)
	}()

	m.logger.Info("session started",
		"session_id", id,
		"name", name,
		"argv", argv,
		"pty", req.PTY,
	)
	return s, nil
}

// Delete removes a session record. If it's still running, signal it first.
// Always best-effort — does not block on the process actually exiting.
func (m *Manager) Delete(id string) error {
	m.mu.Lock()
	s, ok := m.byID[id]
	if !ok {
		m.mu.Unlock()
		return ErrNotFound
	}
	delete(m.byID, id)
	if m.byName[s.name] == s {
		delete(m.byName, s.name)
	}
	m.mu.Unlock()
	s.shutdown()
	return nil
}

// runSweeper deletes recordings older than the retention window. Runs
// forever until Close is called.
func (m *Manager) runSweeper() {
	if m.cfg.RecordingRetention <= 0 {
		return
	}
	ticker := time.NewTicker(m.cfg.SweepInterval)
	defer ticker.Stop()
	// Run once immediately so a process restart cleans up stale state.
	m.sweepOnce()
	for {
		select {
		case <-m.closeCh:
			return
		case <-ticker.C:
			m.sweepOnce()
		}
	}
}

func (m *Manager) sweepOnce() {
	dir := filepath.Join(m.cfg.RecordingDir, m.cfg.SandboxID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-m.cfg.RecordingRetention)
	live := map[string]struct{}{}
	m.mu.Lock()
	for id := range m.byID {
		live[id+".cast"] = struct{}{}
	}
	m.mu.Unlock()

	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".cast") {
			continue
		}
		// Never prune a recording for a session that is still tracked,
		// even if the file is technically older than the retention.
		if _, ok := live[e.Name()]; ok {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			path := filepath.Join(dir, e.Name())
			if err := os.Remove(path); err != nil {
				m.logger.Debug("recording prune failed", "path", path, "error", err)
			}
		}
	}
}

// ErrNotFound is returned when a session ID isn't tracked.
var ErrNotFound = errors.New("session not found")

func newSessionID() (string, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "ses-" + hex.EncodeToString(buf), nil
}

func mergeEnv(extra map[string]string) []string {
	base := append([]string{}, os.Environ()...)
	for k, v := range extra {
		base = append(base, k+"="+v)
	}
	return base
}

func orDefault(v, fallback int) int {
	if v <= 0 {
		return fallback
	}
	return v
}

// buildArgv resolves the final argv from a CreateSessionRequest. If both
// Argv and Command are empty, defaults to a login shell.
func buildArgv(req models.CreateSessionRequest) ([]string, error) {
	if len(req.Argv) > 0 {
		return append([]string{}, req.Argv...), nil
	}
	if cmd := strings.TrimSpace(req.Command); cmd != "" {
		shell := detectShell()
		return []string{shell, "-c", cmd}, nil
	}
	// Default: a login shell. Prefer bash, fall back to sh.
	shell := detectShell()
	if filepath.Base(shell) == "bash" {
		return []string{shell, "-l"}, nil
	}
	return []string{shell, "-l"}, nil
}

func detectShell() string {
	if path, err := exec.LookPath("bash"); err == nil {
		return path
	}
	if path, err := exec.LookPath("sh"); err == nil {
		return path
	}
	return "/bin/sh"
}
