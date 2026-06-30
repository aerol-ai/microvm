package docker

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/pkg/readyproto"
)

const (
	// GuestReadySocketPath is the in-container path toolboxd dials.
	GuestReadySocketPath = "/run/aerol/ready.sock"
	readySocketEnv       = "SB_READY_SOCKET"
	readyNonceEnv        = "SB_READY_NONCE"

	readyHealthPollGrace    = 50 * time.Millisecond
	readyConnReadTimeout    = 2 * time.Second
	maxInvalidReadyAttempts = 16
)

var activeReadySockets sync.Map // path -> struct{}

// validateReadySandboxID mirrors the daemon's sandbox ID charset because the
// ID is embedded in a host filesystem path.
func validateReadySandboxID(id string) error {
	if id == "" {
		return errors.New("sandbox ID is empty")
	}
	if len(id) > 128 {
		return fmt.Errorf("sandbox ID exceeds 128 chars (%d)", len(id))
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return fmt.Errorf("invalid character %q in sandbox ID %q", r, id)
		}
	}
	return nil
}

func mintReadyNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// ReadyListener accepts a single valid readiness push from toolboxd.
type ReadyListener struct {
	hostPath   string
	sandboxID  string
	token      string
	nonce      string
	listener   net.Listener
	closed     bool
	closeMu    sync.Mutex
	registered bool
}

// NewReadyListener creates and listens on a per-create unix socket under dir.
// The socket file is nonce-keyed so boot sweeps and retries cannot collide.
func NewReadyListener(dir, sandboxID, token, nonce string) (*ReadyListener, error) {
	sandboxID = strings.TrimSpace(sandboxID)
	token = strings.TrimSpace(token)
	nonce = strings.TrimSpace(nonce)
	if err := validateReadySandboxID(sandboxID); err != nil {
		return nil, err
	}
	if token == "" {
		return nil, errors.New("toolbox token is required")
	}
	if nonce == "" {
		return nil, errors.New("ready nonce is required")
	}
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("ready socket dir is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir ready dir: %w", err)
	}

	hostPath := filepath.Join(dir, sandboxID+"."+nonce+".sock")
	if err := os.Remove(hostPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("unlink stale ready socket: %w", err)
	}

	ln, err := net.Listen("unix", hostPath)
	if err != nil {
		return nil, fmt.Errorf("listen ready socket: %w", err)
	}
	if err := os.Chmod(hostPath, 0o666); err != nil {
		_ = ln.Close()
		_ = os.Remove(hostPath)
		return nil, fmt.Errorf("chmod ready socket: %w", err)
	}

	rl := &ReadyListener{
		hostPath:  hostPath,
		sandboxID: sandboxID,
		token:     token,
		nonce:     nonce,
		listener:  ln,
	}
	activeReadySockets.Store(hostPath, struct{}{})
	rl.registered = true
	return rl, nil
}

// HostSocketPath returns the host-side socket path.
func (l *ReadyListener) HostSocketPath() string {
	if l == nil {
		return ""
	}
	return l.hostPath
}

// BindSpec returns the docker bind mount for this socket.
func (l *ReadyListener) BindSpec() string {
	return fmt.Sprintf("%s:%s:rw", l.hostPath, GuestReadySocketPath)
}

// EnvVars returns the env vars toolboxd needs to dial the socket.
func (l *ReadyListener) EnvVars() []string {
	return []string{
		readySocketEnv + "=" + GuestReadySocketPath,
		readyNonceEnv + "=" + l.nonce,
	}
}

// Wait accepts connections until a valid ready signal arrives or ctx expires.
func (l *ReadyListener) Wait(ctx context.Context) error {
	if l == nil || l.listener == nil {
		return errors.New("ready listener is not configured")
	}
	invalid := 0
	for {
		if err := ctx.Err(); err != nil {
			recordReadySocketTimeout()
			return fmt.Errorf("ready socket wait: %w", err)
		}
		if invalid >= maxInvalidReadyAttempts {
			recordReadySocketInvalid()
			return errors.New("ready socket: too many invalid attempts")
		}

		deadline, ok := ctx.Deadline()
		if !ok {
			deadline = time.Now().Add(30 * time.Second)
		}
		_ = l.listener.(*net.UnixListener).SetDeadline(deadline)

		conn, err := l.listener.Accept()
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				if ctx.Err() != nil {
					recordReadySocketTimeout()
					return fmt.Errorf("ready socket wait: %w", ctx.Err())
				}
				continue
			}
			if ctx.Err() != nil {
				recordReadySocketTimeout()
				return fmt.Errorf("ready socket wait: %w", ctx.Err())
			}
			return fmt.Errorf("ready socket accept: %w", err)
		}

		if err := l.readAndVerify(conn); err != nil {
			invalid++
			recordReadySocketInvalid()
			_ = conn.Close()
			continue
		}
		_ = conn.Close()
		return nil
	}
}

func (l *ReadyListener) readAndVerify(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(readyConnReadTimeout))
	sig, err := readyproto.Decode(bufio.NewReader(conn))
	if err != nil {
		return err
	}
	if sig.SandboxID != l.sandboxID {
		return errors.New("sandbox_id mismatch")
	}
	if sig.Nonce != l.nonce {
		return errors.New("nonce mismatch")
	}
	if subtle.ConstantTimeCompare([]byte(sig.Token), []byte(l.token)) != 1 {
		return errors.New("token mismatch")
	}
	return nil
}

// Close shuts down the listener but deliberately leaves the socket file in
// place. Docker persists bind mounts across stop/start, so the host-side bind
// source must remain present for the container lifetime. Destroy removes the
// sandbox-keyed socket after the container is gone.
func (l *ReadyListener) Close() error {
	if l == nil {
		return nil
	}
	l.closeMu.Lock()
	defer l.closeMu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.registered {
		activeReadySockets.Delete(l.hostPath)
		l.registered = false
	}
	var err error
	if l.listener != nil {
		err = l.listener.Close()
		l.listener = nil
	}
	return err
}

// EnsureReadyDir creates the sandboxd-owned ready-socket parent directory.
func EnsureReadyDir(dir string) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return errors.New("ready socket dir is required")
	}
	return os.MkdirAll(dir, 0o700)
}

// SweepOrphanReadySockets removes stale socket files from a prior crash.
// Paths registered by live creates (activeReadySockets) are skipped.
func SweepOrphanReadySockets(dir string) error {
	return SweepOrphanReadySocketsExcept(dir, nil)
}

// SweepOrphanReadySocketsExcept removes stale socket files while preserving
// paths still referenced by Docker bind mounts. A stopped container cannot
// restart if its persisted bind source disappears.
func SweepOrphanReadySocketsExcept(dir string, keep map[string]struct{}) error {
	dir = strings.TrimSpace(dir)
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, ent := range entries {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".sock") {
			continue
		}
		path := filepath.Join(dir, ent.Name())
		if _, active := activeReadySockets.Load(path); active {
			continue
		}
		if _, ok := keep[path]; ok {
			continue
		}
		_ = os.Remove(path)
	}
	return nil
}

// RemoveReadySocketsForSandbox unlinks any ready sockets keyed to sandboxID.
func RemoveReadySocketsForSandbox(dir, sandboxID string) {
	if strings.TrimSpace(dir) == "" || strings.TrimSpace(sandboxID) == "" {
		return
	}
	matches, _ := filepath.Glob(filepath.Join(dir, sandboxID+".*.sock"))
	for _, path := range matches {
		if _, active := activeReadySockets.Load(path); active {
			continue
		}
		_ = os.Remove(path)
	}
}
