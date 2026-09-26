package service

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestProxyL4WakeConnDialFailWave10(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-proxy", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "127.0.0.1",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	client, server := netPipe(t)
	defer client.Close()
	defer server.Close()
	// Upstream port nothing listens on → dial fails inside readiness window.
	svc.proxyL4WakeConn(ctx, "sb-proxy", 1, server, nil)
}

func netPipe(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	// Use os pipe via unix socket pair substitute: TCP localhost connect to listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var server net.Conn
	done := make(chan struct{})
	go func() {
		defer close(done)
		c, err := ln.Accept()
		if err != nil {
			return
		}
		server = c
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	<-done
	return client, server
}

func TestL4WakeAcceptAndProxyBranchesWave13(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalL4WakeAddr = "127.0.0.1:0"
	svc.cfg.L4WakeMaxPendingPerSandbox = 1
	svc.cfg.L4WakeMaxPendingGlobal = 1
	svc.caddy = caddy.New(config.Config{EnableCaddy: true, Domain: "sandbox.example.com", HTTPClientTimeout: time.Second})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	svc.l4WakeMu.Lock()
	svc.l4WakeTCP = ln
	svc.l4WakeMu.Unlock()
	go svc.acceptL4WakeTCP(ctx, ln)

	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-l4w", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "127.0.0.1",
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute}, WakeArmed: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-l4w", Port: 9, Protocol: models.ExposedPortProtocolTCP, HostPort: 41234, PublicURL: "tcp://x:41234",
		CreatedAt: now,
	})

	conn1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn1.Write([]byte("GARBAGE\n"))
	_ = conn1.Close()

	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn2.Write([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1111 59999\r\n"))
	_ = conn2.Close()

	// Saturate pending so the real exposure PROXY returns immediately (no 30s dial).
	hold, ok := svc.tryAcquireL4Pending("sb-l4w")
	if !ok {
		t.Fatal("expected pending slot")
	}
	conn3, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	_, _ = conn3.Write([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1111 41234\r\n"))
	time.Sleep(30 * time.Millisecond)
	_ = conn3.Close()
	hold()

	cancel()
	_ = ln.Close()
	time.Sleep(20 * time.Millisecond)

	svc.l4WakeMu.Lock()
	svc.l4WakeTCP = ln
	svc.l4WakeMu.Unlock()
	_ = svc.StartL4WakeProxy(context.Background())

	svc.closeAllTLSWakeListeners()
	svc.testL4ActivityInterval = time.Millisecond
	release2, ok := svc.tryAcquireL4Active("sb-l4w")
	if ok {
		svc.l4LimitMu.Lock()
		gen := svc.l4ActivityGenerations["sb-l4w"]
		svc.l4LimitMu.Unlock()
		done := make(chan struct{})
		go func() {
			svc.touchDuringL4Activity("sb-l4w", gen)
			close(done)
		}()
		time.Sleep(3 * time.Millisecond)
		_ = st.Close()
		time.Sleep(3 * time.Millisecond)
		release2()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("touchDuringL4Activity did not exit")
		}
	}
	_ = svc.l4ActivityStillActive("sb-l4w", 0)
	_ = tlsWakeKey("sb-l4w", 443)
}

type acceptOnceErrListener struct {
	net.Listener
	n atomic.Int32
}

func (l *acceptOnceErrListener) Accept() (net.Conn, error) {
	if l.n.Add(1) == 1 {
		return nil, errors.New("temporary accept failure")
	}
	return nil, net.ErrClosed
}

func TestL4WakeAcceptWarnArmsWave15(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	real, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = real.Close()
	ln := &acceptOnceErrListener{Listener: real}
	done := make(chan struct{})
	go func() {
		svc.acceptL4WakeTCP(ctx, ln)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("acceptL4WakeTCP did not exit")
	}

	// TLS accept warn then closed.
	unixPath := t.TempDir() + "/tls.sock"
	uln, err := net.Listen("unix", unixPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = uln.Close()
	tln := &acceptOnceErrListener{Listener: uln}
	done2 := make(chan struct{})
	go func() {
		svc.acceptL4WakeTLS("sb-tls15", 8443, tln)
		close(done2)
	}()
	select {
	case <-done2:
	case <-time.After(2 * time.Second):
		t.Fatal("acceptL4WakeTLS did not exit")
	}
}

func TestScheduleTLSWakeListenerCloseReplaceWave15(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	path, err := svc.ensureTLSWakeListener("sb-sched15", 9443)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if path == "" {
		t.Fatal("empty socket path")
	}
	svc.scheduleTLSWakeListenerClose("sb-sched15", 9443, 50*time.Millisecond)
	// Replace pending timer — covers stop-old-timer arm.
	svc.scheduleTLSWakeListenerClose("sb-sched15", 9443, 50*time.Millisecond)
	time.Sleep(80 * time.Millisecond)

	// closeTLSWakeListener with pending timer present.
	_, _ = svc.ensureTLSWakeListener("sb-sched15b", 9444)
	svc.scheduleTLSWakeListenerClose("sb-sched15b", 9444, time.Hour)
	svc.closeTLSWakeListener("sb-sched15b", 9444)
}

func TestWakeAwareTargetsMissWave15(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	_, _ = svc.WakeAwarePortTarget(ctx, "missing", 80)
	_, _ = svc.WakeAwareL4PortTarget(ctx, "missing", 59999)
	_ = st.Close()
	_, _ = svc.WakeAwarePortTarget(ctx, "x", 80)
	_, _ = svc.WakeAwareL4PortTarget(ctx, "x", 1)
}

func TestProxyL4WakeDialFailWave15(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	now := time.Now().UTC()
	_ = st.Create(ctx, &models.Sandbox{
		ID: "sb-proxy15", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "127.0.0.1",
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute}, WakeArmed: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		time.Sleep(20 * time.Millisecond)
		_ = server.Close()
	}()
	// Port 1 won't accept → dial fail arm inside proxy.
	svc.proxyL4WakeConn(ctx, "sb-proxy15", 1, server, nil)
	_ = client.Close()
}

func TestStartL4WakeProxyListenFailWave15(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	svc.cfg.InternalL4WakeAddr = "127.0.0.1:1" // privileged / likely fail, or bind fail
	svc.caddy = caddy.New(config.Config{EnableCaddy: true, Domain: "x", HTTPClientTimeout: time.Second})
	// Occupy an address then ask Start to bind the same one.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	svc.cfg.InternalL4WakeAddr = ln.Addr().String()
	if err := svc.StartL4WakeProxy(context.Background()); err == nil {
		t.Fatal("expected listen failure on occupied addr")
	}
}

func TestHandleL4WakeNoTCPExposureWave15(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	_ = st.Create(ctxBackground(), &models.Sandbox{
		ID: "sb-http-exp", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(context.Background(), models.ExposedPort{
		SandboxID: "sb-http-exp", Port: 80, Protocol: models.ExposedPortProtocolHTTP,
		HostPort: 41555, PublicURL: "https://x",
	})
	client, server := net.Pipe()
	defer client.Close()
	go func() {
		_, _ = client.Write([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1111 41555\r\n"))
		_ = client.Close()
	}()
	svc.handleL4WakeTCPConn(server)
}

func ctxBackground() context.Context { return context.Background() }

func TestL4ActiveLimitExceededWave15(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.L4WakeMaxActivePerSandbox = 1
	svc.cfg.L4WakeMaxActiveGlobal = 1
	now := time.Now().UTC()
	_ = st.Create(context.Background(), &models.Sandbox{
		ID: "sb-act", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "127.0.0.1",
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute}, WakeArmed: true,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	hold, ok := svc.tryAcquireL4Active("sb-act")
	if !ok {
		t.Fatal("expected active slot")
	}
	defer hold()
	if _, ok := svc.tryAcquireL4Active("sb-act"); ok {
		t.Fatal("expected active limit")
	}
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go svc.proxyL4WakeConn(context.Background(), "sb-act", 9, c1, nil)
	time.Sleep(20 * time.Millisecond)
}

func TestL4WakeTLSListenerBranchesWave16(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	path, err := svc.ensureTLSWakeListener("tls16", 8443)
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	_ = path
	svc.scheduleTLSWakeListenerClose("tls16", 8443, time.Millisecond)
	time.Sleep(5 * time.Millisecond)
	svc.closeTLSWakeListener("tls16", 8443)
	svc.closeTLSWakeListener("tls16", 8443) // idempotent miss
	svc.closeAllTLSWakeListeners()
}

func TestL4WakeGetPortHTTPExposureWave17(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	now := time.Now().UTC()
	_ = st.Create(context.Background(), &models.Sandbox{
		ID: "sb-http-l4", Image: "a", Status: models.SandboxStatusStarted,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st.UpsertPort(context.Background(), models.ExposedPort{
		SandboxID: "sb-http-l4", Port: 80, Protocol: models.ExposedPortProtocolHTTP,
		HostPort: 42000, PublicURL: "https://x", CreatedAt: now,
	})
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		_, _ = c2.Write([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 42000\r\n"))
		_ = c2.Close()
	}()
	svc.handleL4WakeTCPConn(c1)
}

func TestL4WakePendingLimitWave21(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.cfg.L4WakeMaxPendingGlobal = 1
	svc.cfg.L4WakeMaxPendingPerSandbox = 1

	release, ok := svc.tryAcquireL4Pending("sb-lim")
	if !ok {
		t.Fatal("first pending should succeed")
	}
	if _, ok := svc.tryAcquireL4Pending("sb-lim"); ok {
		t.Fatal("second pending should fail")
	}
	release()

	svc.cfg.L4WakeMaxActivePerSandbox = 1
	svc.cfg.L4WakeMaxActiveGlobal = 1
	r1, ok := svc.tryAcquireL4Active("sb-act")
	if !ok {
		t.Fatal("first active")
	}
	if _, ok := svc.tryAcquireL4Active("sb-act"); ok {
		t.Fatal("second active should fail")
	}
	r1()
}

func TestL4WakeProxyLookupAndActiveWave22(t *testing.T) {
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.cfg.L4WakeMaxActivePerSandbox = 1
	svc.cfg.L4WakeMaxActiveGlobal = 1

	// Valid PROXY header → GetPortByHostPort on closed store.
	header := "PROXY TCP4 1.2.3.4 5.6.7.8 1234 37001\r\n"
	client, server := net.Pipe()
	t.Cleanup(func() { _ = client.Close(); _ = server.Close() })
	go func() {
		_, _ = client.Write([]byte(header))
	}()
	_ = st.Close()
	svc.handleL4WakeTCPConn(server)

	// Active limit exceeded on proxyL4WakeConn.
	svc2, st2, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc2.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc2.cfg.L4WakeMaxActivePerSandbox = 1
	svc2.cfg.L4WakeMaxActiveGlobal = 1
	now := time.Now().UTC()
	_ = st2.Create(context.Background(), &models.Sandbox{
		ID: "sb-l4a", Image: "a", Status: models.SandboxStatusStarted, ContainerIP: "127.0.0.1",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	})
	_ = st2.UpsertPort(context.Background(), models.ExposedPort{
		SandboxID: "sb-l4a", Port: 5432, Protocol: models.ExposedPortProtocolTCP, HostPort: 37002,
	})
	hold, ok := svc2.tryAcquireL4Active("sb-l4a")
	if !ok {
		t.Fatal("hold active")
	}
	defer hold()
	c2, s2 := net.Pipe()
	t.Cleanup(func() { _ = c2.Close(); _ = s2.Close() })
	go func() { _, _ = c2.Write([]byte("PROXY TCP4 1.2.3.4 5.6.7.8 1 37002\r\n")) }()
	svc2.handleL4WakeTCPConn(s2)
}

func TestScheduleTLSWakeCloseStaleTimerWave22(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.InternalL4WakeDir = t.TempDir()
	svc.scheduleTLSWakeListenerClose("sb-tls", 443, 5*time.Millisecond)
	key := "sb-tls:443"
	svc.l4WakeMu.Lock()
	delete(svc.pendingTLSClose, key)
	svc.l4WakeMu.Unlock()
	time.Sleep(20 * time.Millisecond)
}

func TestProxyL4WakeFailedWakeWave22(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	c, s := net.Pipe()
	t.Cleanup(func() { _ = c.Close(); _ = s.Close() })
	br := bufio.NewReader(bytes.NewReader(nil))
	// Missing sandbox → WakeAwareL4PortTarget fails after pending acquire.
	svc.proxyL4WakeConn(context.Background(), "missing-sb", 1, s, br)
}

func TestReadProxyV1EdgesWave22(t *testing.T) {
	if _, err := readProxyV1DestinationPort(bufio.NewReader(strings.NewReader(strings.Repeat("x", 2000) + "\n"))); err == nil {
		t.Fatal("expected buffer full")
	}
	if _, err := readProxyV1DestinationPort(bufio.NewReader(strings.NewReader("PROXY TCP4 a b c d bad\n"))); err == nil {
		t.Fatal("expected bad port")
	}
	if _, err := readProxyV1DestinationPort(bufio.NewReader(strings.NewReader("PROXY UNIX a b c d 1\n"))); err == nil {
		t.Fatal("expected bad family")
	}
}

func TestL4WakeLimitHelpersWave3(t *testing.T) {
	svc := &Service{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:    config.Config{L4WakeMaxPendingPerSandbox: 1, L4WakeMaxPendingGlobal: 2},
	}
	release, ok := svc.tryAcquireL4Pending("sb-l4")
	if !ok || release == nil {
		t.Fatal("first pending acquire should succeed")
	}
	_, ok = svc.tryAcquireL4Pending("sb-l4")
	if ok {
		t.Fatal("per-sandbox pending cap should reject second acquire")
	}
	release()
	svc.releaseL4Pending("sb-l4") // idempotent when already zero

	activeRelease, ok := svc.tryAcquireL4Active("sb-active")
	if !ok || activeRelease == nil {
		t.Fatal("active acquire should succeed")
	}
	activeRelease()
	svc.releaseL4Active("sb-active")
}

func TestStartL4WakeProxyAddrWave8(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	svc.cfg.InternalL4WakeAddr = ""
	svc.caddy = caddy.New(config.Config{EnableCaddy: true, HTTPClientTimeout: time.Second})
	if err := svc.StartL4WakeProxy(context.Background()); err != nil {
		t.Fatalf("empty addr should no-op: %v", err)
	}

	// Bind a real listener then ask StartL4WakeProxy to use the same addr → listen fail.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	svc.cfg.InternalL4WakeAddr = ln.Addr().String()
	if err := svc.StartL4WakeProxy(context.Background()); err == nil {
		t.Fatal("expected listen failure")
	}
}

func TestStartL4WakeProxyIdempotentAndAcceptWave9(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableServerless = true
	svc.cfg.EnableCaddy = true
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	svc.cfg.InternalL4WakeAddr = addr
	if err := svc.StartL4WakeProxy(ctx); err != nil {
		t.Fatalf("StartL4WakeProxy: %v", err)
	}
	// Second call hits already-listening arm.
	if err := svc.StartL4WakeProxy(ctx); err != nil {
		t.Fatalf("idempotent StartL4WakeProxy: %v", err)
	}
	// Empty addr no-op.
	svc2, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc2.cfg.EnableServerless = true
	svc2.cfg.EnableCaddy = true
	svc2.cfg.InternalL4WakeAddr = ""
	if err := svc2.StartL4WakeProxy(ctx); err != nil {
		t.Fatal(err)
	}
}
