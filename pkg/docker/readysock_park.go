package docker

import (
	"bufio"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/version"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

const poolParkedEnv = "SB_POOL_PARKED"

// ParkedListener accepts a parked hello and holds the connection for adopt.
type ParkedListener struct {
	hostPath       string
	bootstrapToken string
	parkNonce      string
	listener       net.Listener
	conn           net.Conn
	connMu         sync.Mutex
	closed         bool
	closeMu        sync.Mutex
	registered     bool
}

// NewParkedListener listens for a warm-pool parked hello.
func NewParkedListener(dir, slotID, bootstrapToken, parkNonce string) (*ParkedListener, error) {
	slotID = strings.TrimSpace(slotID)
	bootstrapToken = strings.TrimSpace(bootstrapToken)
	parkNonce = strings.TrimSpace(parkNonce)
	if slotID == "" {
		return nil, errors.New("park slot id is required")
	}
	if bootstrapToken == "" || parkNonce == "" {
		return nil, errors.New("park bootstrap token and nonce are required")
	}
	if strings.TrimSpace(dir) == "" {
		return nil, errors.New("ready socket dir is required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir ready dir: %w", err)
	}

	hostPath := parkSocketHostPath(dir, slotID)
	if len(hostPath) > maxUnixSocketPathLen {
		return nil, fmt.Errorf("park socket path exceeds %d bytes: %s", maxUnixSocketPathLen, hostPath)
	}
	if err := os.Remove(hostPath); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("unlink stale park socket: %w", err)
	}

	ln, err := net.Listen("unix", hostPath)
	if err != nil {
		return nil, fmt.Errorf("listen park socket: %w", err)
	}
	if err := os.Chmod(hostPath, 0o666); err != nil {
		_ = ln.Close()
		_ = os.Remove(hostPath)
		return nil, fmt.Errorf("chmod park socket: %w", err)
	}

	pl := &ParkedListener{
		hostPath:       hostPath,
		bootstrapToken: bootstrapToken,
		parkNonce:      parkNonce,
		listener:       ln,
	}
	activeReadySockets.Store(hostPath, struct{}{})
	pl.registered = true
	return pl, nil
}

func parkSocketHostPath(dir, slotID string) string {
	return filepath.Join(dir, slotID+".sock")
}

// HostSocketPath returns the host-side socket path.
func (l *ParkedListener) HostSocketPath() string {
	if l == nil {
		return ""
	}
	return l.hostPath
}

// BindSpec returns the docker bind mount for this socket.
func (l *ParkedListener) BindSpec() string {
	return fmt.Sprintf("%s:%s:rw", l.hostPath, GuestReadySocketPath)
}

// EnvVars returns env vars for a parked container.
func (l *ParkedListener) EnvVars() []string {
	return []string{
		poolParkedEnv + "=1",
		readySocketEnv + "=" + GuestReadySocketPath,
		readyNonceEnv + "=" + l.parkNonce,
	}
}

// WaitParked accepts one valid parked hello and retains the connection.
func (l *ParkedListener) WaitParked(ctx context.Context) error {
	if l == nil || l.listener == nil {
		return errors.New("park listener is not configured")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(30 * time.Second)
	}
	_ = l.listener.(*net.UnixListener).SetDeadline(deadline)

	conn, err := l.listener.Accept()
	if err != nil {
		return fmt.Errorf("park socket accept: %w", err)
	}
	if err := l.verifyParked(conn); err != nil {
		_ = conn.Close()
		return err
	}
	l.connMu.Lock()
	l.conn = conn
	l.connMu.Unlock()
	return nil
}

func (l *ParkedListener) verifyParked(conn net.Conn) error {
	_ = conn.SetDeadline(time.Now().Add(readyConnReadTimeout))
	sig, err := readyproto.DecodeParked(bufio.NewReader(conn))
	if err != nil {
		return err
	}
	if sig.Nonce != l.parkNonce {
		return errors.New("park nonce mismatch")
	}
	if subtle.ConstantTimeCompare([]byte(sig.Token), []byte(l.bootstrapToken)) != 1 {
		return errors.New("park token mismatch")
	}
	if sig.AgentVersion != "" && sig.AgentVersion != version.Version {
		return fmt.Errorf("toolbox agent version mismatch: guest %q host %q", sig.AgentVersion, version.Version)
	}
	return nil
}

// Alive reports whether the held parked connection is still open.
func (l *ParkedListener) Alive() bool {
	if l == nil {
		return false
	}
	l.connMu.Lock()
	defer l.connMu.Unlock()
	return l.conn != nil && !l.closed
}

// Adopt sends the adopt frame and waits for the ready ack.
func (l *ParkedListener) Adopt(ctx context.Context, sandboxID, token, adoptNonce string) error {
	if l == nil {
		return errors.New("park listener is nil")
	}
	l.connMu.Lock()
	conn := l.conn
	l.connMu.Unlock()
	if conn == nil {
		return errors.New("park connection is not held")
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(readyConnReadTimeout)
	}
	_ = conn.SetDeadline(deadline)

	if err := readyproto.EncodeAdopt(conn, readyproto.AdoptFrame{
		Event:     readyproto.EventAdopt,
		SandboxID: sandboxID,
		Token:     token,
		Nonce:     adoptNonce,
	}); err != nil {
		return fmt.Errorf("send adopt: %w", err)
	}

	sig, err := readyproto.Decode(bufio.NewReader(conn))
	if err != nil {
		return fmt.Errorf("adopt ack: %w", err)
	}
	if sig.SandboxID != sandboxID || sig.Nonce != adoptNonce {
		return errors.New("adopt ack identity mismatch")
	}
	if subtle.ConstantTimeCompare([]byte(sig.Token), []byte(token)) != 1 {
		return errors.New("adopt ack token mismatch")
	}
	_ = conn.Close()
	l.connMu.Lock()
	l.conn = nil
	l.connMu.Unlock()
	return nil
}

// Close shuts down the park listener and any held connection.
func (l *ParkedListener) Close() error {
	if l == nil {
		return nil
	}
	l.closeMu.Lock()
	defer l.closeMu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	l.connMu.Lock()
	if l.conn != nil {
		_ = l.conn.Close()
		l.conn = nil
	}
	l.connMu.Unlock()
	if l.registered {
		activeReadySockets.Delete(l.hostPath)
		l.registered = false
	}
	var err error
	if l.listener != nil {
		err = l.listener.Close()
		l.listener = nil
	}
	_ = os.Remove(l.hostPath)
	return err
}

// RemoveParkSocket unlinks a park socket path if not active.
func RemoveParkSocket(path string) {
	if strings.TrimSpace(path) == "" {
		return
	}
	if _, active := activeReadySockets.Load(path); active {
		return
	}
	_ = os.Remove(path)
}
