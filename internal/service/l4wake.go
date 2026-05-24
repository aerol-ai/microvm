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
	target, err := s.WakeAwareL4PortTarget(ctx, id, port)
	if err != nil {
		s.logger.Warn("l4 wake failed", "sandbox_id", id, "port", port, "error", err)
		return
	}

	upstream, err := net.DialTimeout("tcp", target, l4WakeDialTimeout)
	if err != nil {
		s.logger.Warn("dial l4 wake upstream failed", "sandbox_id", id, "port", port, "target", target, "error", err)
		return
	}
	defer upstream.Close()

	_ = s.TouchSandbox(ctx, id)
	touchCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go s.touchDuringL4Connection(touchCtx, id)

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

func (s *Service) touchDuringL4Connection(ctx context.Context, id string) {
	ticker := time.NewTicker(l4WakeActivityInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.TouchSandbox(ctx, id); err != nil {
				s.logger.Warn("touch l4 wake connection failed", "sandbox_id", id, "error", err)
			}
		}
	}
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
