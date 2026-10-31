package pkcs11

import (
	"context"
	"encoding/json"
	"errors"
	"expvar"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aerol-ai/microvm/pkg/secrets"
)

// HelperFlag starts `sandboxd` as the PKCS#11 helper (cmd/sandboxd).
const HelperFlag = "--pkcs11-helper"

const (
	restartBackoff = 100 * time.Millisecond
	maxBackoff     = 5 * time.Second
	pollInterval   = 50 * time.Millisecond
)

// StartTimeout covers C_Initialize, login, the IV probe and the first key
// lookup in a fresh helper.
const StartTimeout = 15 * time.Second

// startTimeoutOverride, when set, replaces StartTimeout (tests only).
var startTimeoutOverride atomic.Int64

func startTimeout() time.Duration {
	if d := startTimeoutOverride.Load(); d > 0 {
		return time.Duration(d)
	}
	return StartTimeout
}

// Restart reasons for aerolvm_pkcs11_helper_restarts_total{reason}.
const (
	RestartExit     = "exit"
	RestartDeadline = "deadline"
)

// helperRestarts counts helper replacements by reason (eng D25): "exit" for
// a helper that died, "deadline" for one killed after holding an op past
// OpDeadline.
var helperRestarts = expvar.NewMap("aerolvm_pkcs11_helper_restarts_total")

// proc is a running helper process.
type proc interface {
	Wait() error
	Kill() error
}

// starter launches a helper that serves on socket.
type starter func(socket string) (proc, error)

// HelperOptions configures the sandboxd side of the helper.
type HelperOptions struct {
	// Socket is the helper's Unix socket. Its directory is made 0700, and
	// the helper makes the socket 0600.
	Socket string
	Token  TokenConfig
	// start replaces ExecStarter in tests.
	start starter
}

// Helper is the sandboxd side of the PKCS#11 helper (eng D5): a
// secrets.DataKeyWrapper that forwards each call over the helper's socket and
// keeps the helper running. The vendor library never loads into sandboxd, so
// a vendor crash costs a helper restart, not the daemon.
type Helper struct {
	opts HelperOptions

	mu      sync.Mutex
	proc    proc
	gen     uint64
	ready   bool
	reason  string // why the current process is being replaced
	info    Info
	closed  bool
	exited  chan struct{}
	stopped chan struct{}
}

// StartHelper launches the helper and waits until it serves. It always
// returns a Helper whose supervisor keeps (re)starting the helper; the error
// is the first start's, so boot can refuse under strict boot or warn and
// carry on, as for the other providers.
func StartHelper(opts HelperOptions) (*Helper, error) {
	if opts.start == nil {
		opts.start = ExecStarter(opts.Token)
	}
	h := &Helper{opts: opts, stopped: make(chan struct{})}
	if err := os.MkdirAll(dirOf(opts.Socket), 0o700); err != nil {
		return nil, fmt.Errorf("create pkcs11 helper socket directory: %w", err)
	}
	if err := os.Chmod(dirOf(opts.Socket), 0o700); err != nil {
		return nil, fmt.Errorf("lock down pkcs11 helper socket directory: %w", err)
	}
	err := h.launch()
	go h.supervise(err != nil)
	return h, err
}

func dirOf(path string) string {
	if i := strings.LastIndex(path, "/"); i > 0 {
		return path[:i]
	}
	return "."
}

// ExecStarter runs this same binary with HelperFlag and the token settings
// as flags. The helper exits when its parent does.
func ExecStarter(cfg TokenConfig) starter {
	return func(socket string) (proc, error) {
		exe, err := os.Executable()
		if err != nil {
			return nil, err
		}
		cmd := exec.Command(exe, append([]string{HelperFlag}, helperArgs(socket, cfg)...)...)
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			return nil, err
		}
		return cmdProc{cmd}, nil
	}
}

func helperArgs(socket string, cfg TokenConfig) []string {
	return []string{
		"--socket", socket,
		"--parent", strconv.Itoa(os.Getpid()),
		"--module", cfg.Module,
		"--token-label", cfg.TokenLabel,
		"--pin-file", cfg.PINFile,
		"--key-label", cfg.KeyLabel,
		"--decrypt-key-labels", strings.Join(cfg.DecryptLabels, ","),
		"--gcm-iv", cfg.IVMode,
		"--sessions", strconv.Itoa(cfg.Sessions),
	}
}

type cmdProc struct{ cmd *exec.Cmd }

func (p cmdProc) Wait() error { return p.cmd.Wait() }
func (p cmdProc) Kill() error { return p.cmd.Process.Kill() }

func (h *Helper) launch() error {
	_ = os.Remove(h.opts.Socket)
	p, err := h.opts.start(h.opts.Socket)
	if err != nil {
		return fmt.Errorf("%w: start pkcs11 helper: %v", secrets.ErrProviderUnavailable, err)
	}
	exited := make(chan struct{})
	var waitErr error
	go func() { waitErr = p.Wait(); close(exited) }()
	deadline := time.Now().Add(startTimeout())
	var info Info
	for {
		r, err := h.roundTrip(context.Background(), request{Op: opInfo}, time.Now().Add(opDeadline()))
		if err == nil && r.Info != nil {
			info = *r.Info
			break
		}
		select {
		case <-exited:
			return fmt.Errorf("%w: pkcs11 helper exited during start: %v", secrets.ErrProviderUnavailable, waitErr)
		default:
		}
		if time.Now().After(deadline) {
			_ = p.Kill()
			<-exited
			return fmt.Errorf("%w: pkcs11 helper did not serve within %s", secrets.ErrProviderUnavailable, startTimeout())
		}
		time.Sleep(pollInterval)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.proc, h.ready, h.info, h.reason, h.exited = p, true, info, "", exited
	h.gen++
	if h.closed {
		// Close ran while this helper was starting: it must not outlive it.
		h.ready = false
		_ = p.Kill()
	}
	return nil
}

// supervise restarts the helper whenever it exits, with backoff, until Close.
func (h *Helper) supervise(down bool) {
	defer close(h.stopped)
	backoff := restartBackoff
	for {
		if !down {
			h.mu.Lock()
			exited := h.exited
			h.mu.Unlock()
			<-exited
			h.mu.Lock()
			h.ready = false
			reason := h.reason
			if reason == "" {
				reason = RestartExit
			}
			closed := h.closed
			h.mu.Unlock()
			if closed {
				return
			}
			helperRestarts.Add(reason, 1)
		}
		for {
			time.Sleep(backoff)
			if h.isClosed() {
				return
			}
			if err := h.launch(); err == nil {
				backoff = restartBackoff
				down = false
				break
			}
			backoff = min(backoff*2, maxBackoff)
		}
	}
}

func (h *Helper) isClosed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

// Close stops the helper and its supervisor.
func (h *Helper) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	h.ready = false
	p := h.proc
	h.mu.Unlock()
	if p != nil {
		_ = p.Kill()
	}
	<-h.stopped
	_ = os.Remove(h.opts.Socket)
	return nil
}

// Info is what the helper reported about its token at its last start; the
// zero Info until a start succeeds.
func (h *Helper) Info() Info {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.info
}

// CurrentKeyVersion implements secrets.KeyVersioner: the label new wraps
// use, in the form secrets.WrappedKeyVersion reports, so the rewrap sweep
// moves rows on older labels to it (§11, eng D23).
func (h *Helper) CurrentKeyVersion(context.Context) (string, error) {
	label := h.Info().KeyLabel
	if label == "" {
		return "", fmt.Errorf("%w: the pkcs11 helper has not started", secrets.ErrProviderUnavailable)
	}
	return "p11:" + label, nil
}

// DecryptableKeyVersions lists the labels this node still opens, current
// first, for aerolvm_key_decryptable (eng D23: a rotation waits until every
// member can open the new label before switching to it).
func (h *Helper) DecryptableKeyVersions() []string {
	info := h.Info()
	if info.KeyLabel == "" {
		return nil
	}
	out := []string{"p11:" + info.KeyLabel}
	for _, l := range info.DecryptLabels {
		out = append(out, "p11:"+l)
	}
	return out
}

// Wrap implements secrets.DataKeyWrapper.
func (h *Helper) Wrap(ctx context.Context, dek []byte, encCtx map[string]string) ([]byte, error) {
	return h.call(ctx, request{Op: opWrap, Data: dek, AAD: secrets.EncryptionContextAAD(encCtx)})
}

// Unwrap implements secrets.DataKeyWrapper.
func (h *Helper) Unwrap(ctx context.Context, wrapped []byte, encCtx map[string]string) ([]byte, error) {
	return h.call(ctx, request{Op: opUnwrap, Data: wrapped, AAD: secrets.EncryptionContextAAD(encCtx)})
}

func (h *Helper) call(ctx context.Context, req request) ([]byte, error) {
	h.mu.Lock()
	ready, gen := h.ready, h.gen
	h.mu.Unlock()
	if !ready {
		return nil, fmt.Errorf("%w: pkcs11 helper is restarting", secrets.ErrProviderUnavailable)
	}
	opEnd := time.Now().Add(opDeadline())
	deadline := opEnd
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	req.Timeout = time.Until(deadline).Milliseconds()
	r, err := h.roundTrip(ctx, req, deadline)
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() && !deadline.Before(opEnd) {
			// The helper held the op past OpDeadline: a vendor call is stuck
			// in C. Only a new process frees its session (eng D25).
			h.kill(gen, RestartDeadline)
		}
		return nil, fmt.Errorf("%w: pkcs11 helper %s: %v", secrets.ErrProviderUnavailable, req.Op, err)
	}
	if err := errFromReply(r); err != nil {
		return nil, err
	}
	return r.Data, nil
}

func (h *Helper) roundTrip(ctx context.Context, req request, deadline time.Time) (reply, error) {
	d := net.Dialer{Deadline: deadline}
	conn, err := d.DialContext(ctx, "unix", h.opts.Socket)
	if err != nil {
		return reply{}, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return reply{}, err
	}
	var r reply
	if err := readJSON(conn, &r); err != nil {
		return reply{}, err
	}
	return r, nil
}

// kill replaces helper generation gen, unless it was already replaced.
func (h *Helper) kill(gen uint64, reason string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if gen != h.gen || !h.ready || h.proc == nil {
		return
	}
	h.ready = false
	h.reason = reason
	_ = h.proc.Kill()
}
