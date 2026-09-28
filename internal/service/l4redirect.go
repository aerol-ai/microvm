package service

import (
	"context"
	"errors"
	"net"

	"github.com/aerol-ai/microvm/pkg/models"
)

// StartL4RedirectListener serves raw-TCP host ports the kernel can't forward
// directly (plans/ingress-proxy-routing.md §3.5): stopped/wake sandboxes and
// WASM/isolate loopback mediators. hostport installs "-j REDIRECT
// --to-ports <this listener>" for them.
//
// A redirected connection carries no PROXY header, which the Caddy-fed wake
// listener relied on. The original host port is read from the kernel with
// SO_ORIGINAL_DST instead. A connection made to this listener directly (not
// redirected) reports this listener's own port, matches no exposure, and is
// closed.
func (s *Service) StartL4RedirectListener(ctx context.Context, addr string) (net.Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	go s.acceptL4Redirect(ctx, ln)
	return ln, nil
}

func (s *Service) acceptL4Redirect(ctx context.Context, ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.logger.Warn("accept l4 redirect connection failed", "error", err)
			continue
		}
		go s.handleL4RedirectConn(conn)
	}
}

func (s *Service) handleL4RedirectConn(conn net.Conn) {
	defer conn.Close()
	originalDst := platformOriginalDstPort
	if s.testOriginalDstPort != nil {
		originalDst = s.testOriginalDstPort
	}
	hostPort, err := originalDst(conn)
	if err != nil {
		s.logger.Warn("l4 redirect: original destination unavailable", "error", err)
		return
	}
	exposure, err := s.store.GetPortByHostPort(context.Background(), hostPort)
	if err != nil || exposure == nil || exposure.Protocol != models.ExposedPortProtocolTCP {
		// Includes direct connections to the listener itself (its own port
		// is not an exposure).
		return
	}
	s.proxyL4WakeConn(context.Background(), exposure.SandboxID, exposure.Port, conn, nil)
}
