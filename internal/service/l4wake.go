package service

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

const (
	l4WakeProxyHeaderMaxBytes = 256
	l4WakeDialTimeout         = 10 * time.Second
	l4WakeActivityInterval    = 30 * time.Second

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

func readProxyV1DestinationPort(br *bufio.Reader) (int, error) {
	line, err := br.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return 0, errors.New("proxy protocol header too large")
	}
	if err != nil {
		return 0, fmt.Errorf("read proxy protocol header: %w", err)
	}
	fields := strings.Fields(strings.TrimSpace(string(line)))
	if len(fields) != 6 || fields[0] != "PROXY" {
		return 0, fmt.Errorf("malformed proxy protocol header %q", strings.TrimSpace(string(line)))
	}
	if fields[1] != "TCP4" && fields[1] != "TCP6" {
		return 0, fmt.Errorf("unsupported proxy protocol family %q", fields[1])
	}
	dstPort, err := strconv.Atoi(fields[5])
	if err != nil || dstPort <= 0 || dstPort > 65535 {
		return 0, fmt.Errorf("invalid proxy protocol destination port %q", fields[5])
	}
	return dstPort, nil
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

	upstream, err := net.DialTimeout("tcp", target, l4WakeDialTimeout)
	if err != nil {
		s.logger.Warn("dial l4 wake upstream failed", "sandbox_id", id, "port", port, "target", target, "error", err)
		return
	}
	defer upstream.Close()

	_ = s.TouchSandbox(ctx, id)

	downstreamReader := io.Reader(downstream)
	if buffered != nil {
		downstreamReader = io.MultiReader(buffered, downstream)
	}

	done := make(chan struct{}, 2)
	go proxyCopyAndCloseWrite(upstream, downstreamReader, done)
	go proxyCopyAndCloseWrite(downstream, upstream, done)
	<-done
	_ = downstream.Close()
	_ = upstream.Close()
}

func (s *Service) tryAcquireL4Pending(id string) (func(), bool) {
	perSandboxMax := s.l4WakeMaxPendingPerSandbox()
	globalMax := s.l4WakeMaxPendingGlobal()

	s.l4LimitMu.Lock()
	defer s.l4LimitMu.Unlock()
	if s.l4PendingBySandbox == nil {
		s.l4PendingBySandbox = make(map[string]int)
	}
	if s.l4PendingBySandbox[id] >= perSandboxMax || s.l4PendingGlobal >= globalMax {
		return nil, false
	}
	s.l4PendingBySandbox[id]++
	s.l4PendingGlobal++
	return func() {
		s.releaseL4Pending(id)
	}, true
}

func (s *Service) releaseL4Pending(id string) {
	s.l4LimitMu.Lock()
	defer s.l4LimitMu.Unlock()
	if s.l4PendingBySandbox[id] <= 1 {
		delete(s.l4PendingBySandbox, id)
	} else {
		s.l4PendingBySandbox[id]--
	}
	if s.l4PendingGlobal > 0 {
		s.l4PendingGlobal--
	}
}

func (s *Service) tryAcquireL4Active(id string) (func(), bool) {
	perSandboxMax := s.l4WakeMaxActivePerSandbox()
	globalMax := s.l4WakeMaxActiveGlobal()
	var (
		startTicker bool
		generation  uint64
	)

	s.l4LimitMu.Lock()
	if s.l4ActiveBySandbox == nil {
		s.l4ActiveBySandbox = make(map[string]int)
	}
	if s.l4ActivityGenerations == nil {
		s.l4ActivityGenerations = make(map[string]uint64)
	}
	if s.l4ActiveBySandbox[id] >= perSandboxMax || s.l4ActiveGlobal >= globalMax {
		s.l4LimitMu.Unlock()
		return nil, false
	}
	if s.l4ActiveBySandbox[id] == 0 {
		s.l4ActivitySeq++
		generation = s.l4ActivitySeq
		s.l4ActivityGenerations[id] = generation
		startTicker = true
	}
	s.l4ActiveBySandbox[id]++
	s.l4ActiveGlobal++
	s.l4LimitMu.Unlock()
	if startTicker {
		go s.touchDuringL4Activity(id, generation)
	}
	return func() {
		s.releaseL4Active(id)
	}, true
}

func (s *Service) releaseL4Active(id string) {
	s.l4LimitMu.Lock()
	defer s.l4LimitMu.Unlock()
	if s.l4ActiveBySandbox[id] <= 1 {
		delete(s.l4ActiveBySandbox, id)
		delete(s.l4ActivityGenerations, id)
	} else {
		s.l4ActiveBySandbox[id]--
	}
	if s.l4ActiveGlobal > 0 {
		s.l4ActiveGlobal--
	}
}

func (s *Service) touchDuringL4Activity(id string, generation uint64) {
	ticker := time.NewTicker(l4WakeActivityInterval)
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
	s.l4LimitMu.Lock()
	defer s.l4LimitMu.Unlock()
	return s.l4ActiveBySandbox[id] > 0 && s.l4ActivityGenerations[id] == generation
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

func proxyCopyAndCloseWrite(dst net.Conn, src io.Reader, done chan<- struct{}) {
	_, _ = io.Copy(dst, src)
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	} else {
		_ = dst.Close()
	}
	done <- struct{}{}
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
	if ln, ok := s.l4WakeTLS[key]; ok {
		_ = ln.Close()
		delete(s.l4WakeTLS, key)
	}
	s.l4WakeMu.Unlock()
	_ = os.Remove(path)
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
