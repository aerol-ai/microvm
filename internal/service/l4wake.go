package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aerol-ai/microvm/internal/netsplice"
	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	l4WakeProxyHeaderMaxBytes = 256
	l4WakeDialTimeout         = 10 * time.Second
	l4WakeActivityInterval    = 30 * time.Second
	// l4WakeUpstreamReadyTimeout bounds how long we keep retrying the
	// upstream dial on ECONNREFUSED after wake. WakeAwareL4PortTarget
	// returns as soon as the container is running, but the user's TCP
	// process inside (SOCKS5 server, database, etc.) typically needs
	// another moment to bind its listening port. Without retry the
	// kernel returns ECONNREFUSED instantly and the client connection
	// is closed. 30s leaves headroom for slow framework boots.
	l4WakeUpstreamReadyTimeout = 30 * time.Second
	// l4WakeUpstreamReadyBackoffStart / Max bound the retry cadence
	// during the readiness window; matches the HTTP ingress probe.
	l4WakeUpstreamReadyBackoffStart = 100 * time.Millisecond
	l4WakeUpstreamReadyBackoffMax   = 1 * time.Second

	defaultL4WakeMaxPendingPerSandbox = 256
	defaultL4WakeMaxPendingGlobal     = 4096
	defaultL4WakeMaxActivePerSandbox  = 4096
	defaultL4WakeMaxActiveGlobal      = 65536
)

// StartL4WakeProxy starts the loopback TCP wake listener used by raw-TCP
// serverless routes. TLS-SNI wake uses per-exposure Unix sockets installed by
// ensureTLSWakeListener, but those listeners are also closed from this context.
func (s *Service) StartL4WakeProxy(ctx context.Context) error {
	if !s.cfg.EnableServerless || s.caddy == nil || !s.caddy.Enabled() {
		return nil
	}
	addr := strings.TrimSpace(s.cfg.InternalL4WakeAddr)
	if addr == "" {
		return nil
	}

	s.l4WakeMu.Lock()
	if s.l4WakeTCP != nil {
		s.l4WakeMu.Unlock()
		return nil
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		s.l4WakeMu.Unlock()
		return fmt.Errorf("listen l4 wake proxy: %w", err)
	}
	s.l4WakeTCP = ln
	s.l4WakeMu.Unlock()

	go func() {
		<-ctx.Done()
		_ = ln.Close()
		s.closeAllTLSWakeListeners()
	}()
	go s.acceptL4WakeTCP(ctx, ln)
	return nil
}

func (s *Service) acceptL4WakeTCP(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Warn("accept l4 wake tcp connection failed", "error", err)
			continue
		}
		go s.handleL4WakeTCPConn(conn)
	}
}

func (s *Service) handleL4WakeTCPConn(conn net.Conn) {
	defer conn.Close()

	br := bufio.NewReaderSize(conn, l4WakeProxyHeaderMaxBytes)
	hostPort, err := readProxyV1DestinationPort(br)
	if err != nil {
		s.logger.Warn("invalid l4 wake proxy protocol header", "error", err)
		return
	}
	exposure, err := s.store.GetPortByHostPort(context.Background(), hostPort)
	if err != nil {
		s.logger.Warn("lookup l4 wake host port failed", "host_port", hostPort, "error", err)
		return
	}
	if exposure == nil || exposure.Protocol != models.ExposedPortProtocolTCP {
		s.logger.Warn("l4 wake host port has no tcp exposure", "host_port", hostPort)
		return
	}

	s.proxyL4WakeConn(context.Background(), exposure.SandboxID, exposure.Port, conn, br)
}

// WakeAwareL4PortTarget resolves a raw TCP upstream, ensuring the sandbox is
// awake first. It is shared by raw TCP and TLS-SNI wake proxying.
func (s *Service) WakeAwareL4PortTarget(ctx context.Context, id string, port int) (string, error) {
	sandbox, err := s.EnsureSandboxAwakeForHTTP(ctx, id)
	if err != nil {
		return "", err
	}
	if sandbox == nil || sandbox.ContainerIP == "" {
		fresh, getErr := s.store.Get(ctx, id)
		if getErr != nil {
			return "", getErr
		}
		sandbox = fresh
	}
	if sandbox.ContainerIP == "" {
		return "", errors.New("sandbox container IP is not available")
	}
	exposure := findExposure(sandbox, port)
	if exposure == nil || exposure.Protocol == "" || exposure.Protocol == models.ExposedPortProtocolHTTP {
		return "", fmt.Errorf("sandbox %s does not expose L4 port %d", id, port)
	}
	return net.JoinHostPort(sandbox.ContainerIP, strconv.Itoa(port)), nil
}

// dialL4Upstream connects to addr with retry on any transient dial
// error. This is the L4 counterpart to the HTTP ingress upstream
// readiness probe: the wake helper returns as soon as Docker reports
// the container running, but the user's TCP process (SOCKS5 server,
// database, etc.) typically needs another second or two to bind its
// listening port. A single dial fails immediately on the kernel RST
// and the caller's connection closes.
//
// Retries on any error except caller cancellation / deadline. Docker
// bridge networks during container start can briefly emit
// EHOSTUNREACH, ENETUNREACH, or ECONNRESET in addition to the usual
// ECONNREFUSED — narrowing the retry to only ECONNREFUSED would
// surface those races to the client. Initial backoff carries 0-50ms
// jitter so a convoy of waiters released by one wake doesn't all
// dial in lockstep. Overridable in tests via setDialL4UpstreamForTest.
func dialL4Upstream(ctx context.Context, addr string, budget time.Duration) (net.Conn, error) {
	dialL4UpstreamMu.RLock()
	fn := dialL4UpstreamFn
	dialL4UpstreamMu.RUnlock()
	return fn(ctx, addr, budget)
}

var (
	dialL4UpstreamMu sync.RWMutex
	dialL4UpstreamFn = defaultDialL4Upstream
)

func defaultDialL4Upstream(ctx context.Context, addr string, budget time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(budget)
	dialCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	// Jitter the initial delay so 10k waiters released by a wake do
	// not all dial at exactly t+100ms. math/rand global is
	// concurrent-safe since Go 1.20.
	delay := l4WakeUpstreamReadyBackoffStart + time.Duration(rand.Int63n(int64(50*time.Millisecond)))
	var lastErr error
	for {
		if err := dialCtx.Err(); err != nil {
			if lastErr != nil {
				return nil, lastErr
			}
			return nil, err
		}
		dialer := net.Dialer{Timeout: l4WakeDialTimeout}
		conn, err := dialer.DialContext(dialCtx, "tcp", addr)
		if err == nil {
			return conn, nil
		}
		// Caller cancellation / deadline are terminal — don't keep
		// dialling against a dead caller. Everything else is treated
		// as the "container is up but service not bound yet" signal.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil, err
		}
		lastErr = err
		select {
		case <-dialCtx.Done():
			return nil, lastErr
		case <-time.After(delay):
		}
		if delay < l4WakeUpstreamReadyBackoffMax {
			delay *= 2
			if delay > l4WakeUpstreamReadyBackoffMax {
				delay = l4WakeUpstreamReadyBackoffMax
			}
		}
	}
}

func (s *Service) proxyL4WakeConn(ctx context.Context, id string, port int, downstream net.Conn, buffered *bufio.Reader) {
	releasePending, ok := s.tryAcquireL4Pending(id)
	if !ok {
		s.logger.Warn("l4 wake pending limit exceeded", "sandbox_id", id, "port", port)
		return
	}
	target, err := s.WakeAwareL4PortTarget(ctx, id, port)
	releasePending()
	if err != nil {
		s.logger.Warn("l4 wake failed", "sandbox_id", id, "port", port, "error", err)
		return
	}

	releaseActive, ok := s.tryAcquireL4Active(id)
	if !ok {
		s.logger.Warn("l4 wake active limit exceeded", "sandbox_id", id, "port", port)
		return
	}
	defer releaseActive()

	upstream, err := dialL4Upstream(ctx, target, l4WakeUpstreamReadyTimeout)
	if err != nil {
		s.logger.Warn("dial l4 wake upstream failed", "sandbox_id", id, "port", port, "target", target, "error", err)
		return
	}
	defer upstream.Close()

	_ = s.TouchSandbox(ctx, id)

	// No idle timeout: wake-proxied database connections legitimately sit
	// idle for hours, and the active slot is held until both directions end.
	if err := netsplice.Splice(downstream, upstream, buffered); err != nil {
		s.logger.Warn("l4 wake splice failed", "sandbox_id", id, "port", port, "error", err)
	}
}

// l4Limiters returns the wake proxy's pending and active limiters, created
// on first use so a zero-value Service (as tests build it) works.
func (s *Service) l4Limiters() (pending, active *netsplice.Limiter) {
	s.l4LimitersOnce.Do(func() {
		s.l4Pending = netsplice.NewLimiter(s.l4WakeMaxPendingPerSandbox, s.l4WakeMaxPendingGlobal)
		s.l4Active = netsplice.NewLimiter(s.l4WakeMaxActivePerSandbox, s.l4WakeMaxActiveGlobal)
	})
	return s.l4Pending, s.l4Active
}

func (s *Service) tryAcquireL4Pending(id string) (func(), bool) {
	pending, _ := s.l4Limiters()
	return pending.TryAcquire(id, nil, nil)
}

// tryAcquireL4Active admits one proxied connection. The first connection for
// a sandbox starts one activity ticker, keyed by a generation, so a ticker
// from an earlier burst stops instead of touching on behalf of the new one.
func (s *Service) tryAcquireL4Active(id string) (func(), bool) {
	_, active := s.l4Limiters()
	var (
		startTicker bool
		generation  uint64
	)
	release, ok := active.TryAcquire(id, func(first bool) {
		if !first {
			return
		}
		if s.l4ActivityGenerations == nil {
			s.l4ActivityGenerations = make(map[string]uint64)
		}
		s.l4ActivitySeq++
		generation = s.l4ActivitySeq
		s.l4ActivityGenerations[id] = generation
		startTicker = true
	}, func(last bool) {
		if last {
			delete(s.l4ActivityGenerations, id)
		}
	})
	if !ok {
		return nil, false
	}
	if startTicker {
		go s.touchDuringL4Activity(id, generation)
	}
	return release, true
}

// l4ActivityGeneration reads the current activity generation for id under
// the active limiter's lock (tests and diagnostics).
func (s *Service) l4ActivityGeneration(id string) uint64 {
	_, active := s.l4Limiters()
	var gen uint64
	active.WithLock(id, func(int) { gen = s.l4ActivityGenerations[id] })
	return gen
}

func (s *Service) touchDuringL4Activity(id string, generation uint64) {
	interval := l4WakeActivityInterval
	if s.testL4ActivityInterval > 0 {
		interval = s.testL4ActivityInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		<-ticker.C
		if !s.l4ActivityStillActive(id, generation) {
			return
		}
		if err := s.TouchSandbox(context.Background(), id); err != nil {
			s.logger.Warn("touch l4 wake connection failed", "sandbox_id", id, "error", err)
		}
	}
}

func (s *Service) l4ActivityStillActive(id string, generation uint64) bool {
	_, active := s.l4Limiters()
	var still bool
	active.WithLock(id, func(count int) {
		still = count > 0 && s.l4ActivityGenerations[id] == generation
	})
	return still
}

func (s *Service) l4WakeMaxPendingPerSandbox() int {
	if s.cfg.L4WakeMaxPendingPerSandbox > 0 {
		return s.cfg.L4WakeMaxPendingPerSandbox
	}
	return defaultL4WakeMaxPendingPerSandbox
}

func (s *Service) l4WakeMaxPendingGlobal() int {
	if s.cfg.L4WakeMaxPendingGlobal > 0 {
		return s.cfg.L4WakeMaxPendingGlobal
	}
	return defaultL4WakeMaxPendingGlobal
}

func (s *Service) l4WakeMaxActivePerSandbox() int {
	if s.cfg.L4WakeMaxActivePerSandbox > 0 {
		return s.cfg.L4WakeMaxActivePerSandbox
	}
	return defaultL4WakeMaxActivePerSandbox
}

func (s *Service) l4WakeMaxActiveGlobal() int {
	if s.cfg.L4WakeMaxActiveGlobal > 0 {
		return s.cfg.L4WakeMaxActiveGlobal
	}
	return defaultL4WakeMaxActiveGlobal
}

func (s *Service) ensureTLSWakeListener(id string, port int) (string, error) {
	dir := strings.TrimSpace(s.cfg.InternalL4WakeDir)
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "sandboxd-l4wake")
	}
	socketPath := s.tlsWakeSocketPath(id, port)
	key := tlsWakeKey(id, port)

	s.l4WakeMu.Lock()
	defer s.l4WakeMu.Unlock()
	// A cold→warm→cold flip within the D2 grace window must not leave a
	// timer pending against this key: when it fires it would close the
	// listener the new wake route now depends on.
	if t, ok := s.pendingTLSClose[key]; ok {
		t.Stop()
		delete(s.pendingTLSClose, key)
	}
	if s.l4WakeTLS == nil {
		s.l4WakeTLS = make(map[string]net.Listener)
	}
	if _, ok := s.l4WakeTLS[key]; ok {
		return socketPath, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("create l4 wake socket dir: %w", err)
	}
	_ = os.Chmod(dir, 0o700)
	_ = os.Remove(socketPath)
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		return "", fmt.Errorf("listen l4 wake tls socket: %w", err)
	}
	s.l4WakeTLS[key] = ln
	go s.acceptL4WakeTLS(id, port, ln)
	return socketPath, nil
}

func (s *Service) acceptL4WakeTLS(id string, port int, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Warn("accept l4 wake tls connection failed", "sandbox_id", id, "port", port, "error", err)
			continue
		}
		go func() {
			defer conn.Close()
			s.proxyL4WakeConn(context.Background(), id, port, conn, nil)
		}()
	}
}

func (s *Service) closeTLSWakeListener(id string, port int) {
	key := tlsWakeKey(id, port)
	path := s.tlsWakeSocketPath(id, port)

	s.l4WakeMu.Lock()
	if t, ok := s.pendingTLSClose[key]; ok {
		t.Stop()
		delete(s.pendingTLSClose, key)
	}
	if ln, ok := s.l4WakeTLS[key]; ok {
		_ = ln.Close()
		delete(s.l4WakeTLS, key)
	}
	s.l4WakeMu.Unlock()
	_ = os.Remove(path)
}

// scheduleTLSWakeListenerClose defers a closeTLSWakeListener call by
// delay so a TLS handshake started against the wake-aware route (which
// terminates on the per-exposure Unix socket) can complete before the
// listener goes away. D2 of warm-direct-route-bypass: PATCHing the
// route from wake-aware to direct flips Caddy's view immediately, but
// any handshake mid-stream when PATCH lands is still talking to the
// socket — closing it synchronously drops that connection mid-TLS.
//
// If delay is non-positive (or the bypass flag is off, leaving the
// helper to act like closeTLSWakeListener), the close runs inline so
// tests can poke the lifecycle without sleeping. Any pending timer for
// the same key is replaced — the most recent direct transition is the
// one whose grace window applies.
func (s *Service) scheduleTLSWakeListenerClose(id string, port int, delay time.Duration) {
	if delay <= 0 {
		s.closeTLSWakeListener(id, port)
		return
	}
	key := tlsWakeKey(id, port)
	s.l4WakeMu.Lock()
	defer s.l4WakeMu.Unlock()
	if s.pendingTLSClose == nil {
		s.pendingTLSClose = make(map[string]*time.Timer)
	}
	if t, ok := s.pendingTLSClose[key]; ok {
		t.Stop()
	}
	s.pendingTLSClose[key] = time.AfterFunc(delay, func() {
		// Re-check inside the mutex that this timer is still the
		// authoritative one for the key. A cold→warm→cold sequence may
		// have replaced it; in that case the newer schedule (or
		// ensureTLSWakeListener's cancellation) already owns the
		// lifecycle decision and we must not double-close.
		s.l4WakeMu.Lock()
		current, ok := s.pendingTLSClose[key]
		if !ok || current == nil {
			s.l4WakeMu.Unlock()
			return
		}
		delete(s.pendingTLSClose, key)
		s.l4WakeMu.Unlock()
		s.closeTLSWakeListener(id, port)
	})
}

func (s *Service) closeAllTLSWakeListeners() {
	s.l4WakeMu.Lock()
	listeners := s.l4WakeTLS
	s.l4WakeTLS = nil
	s.l4WakeTCP = nil
	s.l4WakeMu.Unlock()

	for key, ln := range listeners {
		_ = ln.Close()
		parts := strings.Split(key, ":")
		if len(parts) == 2 {
			if port, err := strconv.Atoi(parts[1]); err == nil {
				_ = os.Remove(s.tlsWakeSocketPath(parts[0], port))
			}
		}
	}
}

func (s *Service) tlsWakeSocketPath(id string, port int) string {
	dir := strings.TrimSpace(s.cfg.InternalL4WakeDir)
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "sandboxd-l4wake")
	}
	safeID := strings.NewReplacer("/", "_", "\\", "_", ":", "_").Replace(id)
	return filepath.Join(dir, fmt.Sprintf("%s-%d.sock", safeID, port))
}

func tlsWakeKey(id string, port int) string {
	return fmt.Sprintf("%s:%d", id, port)
}
