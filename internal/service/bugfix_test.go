package service

// Tests for the three bugs found in the AerolVM self-assessment:
//
//   Fix 1 – probeContainerPort and the exposePort gate
//   Fix 2 – ErrSandboxNameConflict → HTTP 409 (tested in pkg/api/apihttp)
//   Fix 3 – createSandbox outer timeout (SB_CREATE_TIMEOUT_SEC)

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// ── Fix 1: probeContainerPort unit tests ─────────────────────────────────────

// TestProbeContainerPortSucceeds binds a real listener and verifies that
// probeContainerPort returns nil — port is open, route can be safely installed.
func TestProbeContainerPortSucceeds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("strconv.Atoi(%q): %v", portStr, err)
	}

	if err := probeContainerPort(context.Background(), host, port); err != nil {
		t.Fatalf("probeContainerPort on open port: %v", err)
	}
}

// TestProbeContainerPortRefused verifies that connection refused is returned
// when nothing is listening on the target port.
func TestProbeContainerPortRefused(t *testing.T) {
	// Bind then immediately close to guarantee the port is free.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	host, portStr, _ := net.SplitHostPort(addr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("strconv.Atoi(%q): %v", portStr, err)
	}

	if err := probeContainerPort(context.Background(), host, port); err == nil {
		t.Fatal("probeContainerPort should fail on a closed port")
	}
}

// TestProbeContainerPortIgnoresCancelledContext verifies that probeContainerPort
// uses its own independent timeout and is NOT affected by a pre-cancelled caller
// context. The probe must reach an open port even when the caller's context is
// already done — this is the intended behaviour so that exposePort works even
// when the surrounding request context is near its deadline.
func TestProbeContainerPortIgnoresCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel the caller context

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen: %v", err)
	}
	defer ln.Close()

	host, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, err2 := strconv.Atoi(portStr)
	if err2 != nil {
		t.Fatalf("strconv.Atoi(%q): %v", portStr, err2)
	}

	// The port is open and the probe uses context.Background() internally,
	// so it must succeed regardless of the cancelled caller context.
	if err := probeContainerPort(ctx, host, port); err != nil {
		t.Fatalf("probeContainerPort should succeed on an open port even with cancelled caller context: %v", err)
	}
}

// ── Fix 1: exposePort integration tests ──────────────────────────────────────

// newProbeSvc returns a Service wired to a real SQLite store and a no-op
// runtime, with the probe function replaced by the supplied stub so tests
// don't attempt real TCP dials.
func newProbeSvc(t *testing.T, probeFn func(ctx context.Context, ip string, port int) error) (*Service, *storepkg.Store) {
	t.Helper()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.probeContainerPortFn = probeFn
	return svc, st
}

func seedStartedSandboxAt(t *testing.T, ctx context.Context, st *storepkg.Store, id, ip string) {
	t.Helper()
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted,
		ContainerID: "ctr-" + id, ContainerIP: ip, Runtime: models.RuntimeDocker,
		CPU: 1, MemoryMB: 256, DiskGB: 5,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox %s: %v", id, err)
	}
}

// TestExposePortProbesOnFirstExpose verifies that the probe is called exactly
// once when a port is exposed for the first time on a started sandbox.
func TestExposePortProbesOnFirstExpose(t *testing.T) {
	ctx := context.Background()
	var probeCalls int
	svc, st := newProbeSvc(t, func(_ context.Context, ip string, port int) error {
		probeCalls++
		return nil // port is open
	})
	seedStartedSandboxAt(t, ctx, st, "sb-probe-first", "10.0.0.10")

	if _, err := svc.ExposePort(ctx, "sb-probe-first", 8080, models.ExposedPortProtocolHTTP); err != nil {
		t.Fatalf("ExposePort: %v", err)
	}
	if probeCalls != 1 {
		t.Fatalf("probe calls = %d, want 1", probeCalls)
	}
}

// TestExposePortSkipsProbeOnReexpose verifies that the probe is NOT called
// when a port was already exposed (re-expose idempotency path).
func TestExposePortSkipsProbeOnReexpose(t *testing.T) {
	ctx := context.Background()
	var probeCalls int
	svc, st := newProbeSvc(t, func(_ context.Context, ip string, port int) error {
		probeCalls++
		return nil
	})
	seedStartedSandboxAt(t, ctx, st, "sb-probe-reexpose", "10.0.0.11")

	now := time.Now().UTC()
	if err := st.UpsertPort(ctx, models.ExposedPort{
		SandboxID: "sb-probe-reexpose", Port: 8080,
		Protocol:  models.ExposedPortProtocolHTTP,
		PublicURL: "https://sb-probe-reexpose-8080.example.com",
		CreatedAt: now,
	}); err != nil {
		t.Fatalf("UpsertPort: %v", err)
	}

	if _, err := svc.ExposePort(ctx, "sb-probe-reexpose", 8080, models.ExposedPortProtocolHTTP); err != nil {
		t.Fatalf("ExposePort: %v", err)
	}
	if probeCalls != 0 {
		t.Fatalf("probe calls = %d, want 0 on re-expose", probeCalls)
	}
}

// TestExposePortSkipsProbeOnEmptyContainerIP verifies that WASM-style sandboxes
// (ContainerIP == "") never trigger the probe.
func TestExposePortSkipsProbeOnEmptyContainerIP(t *testing.T) {
	ctx := context.Background()
	var probeCalls int
	svc, st := newProbeSvc(t, func(_ context.Context, ip string, port int) error {
		probeCalls++
		return nil
	})

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-probe-no-ip", Image: "alpine:3.20",
		Status:      models.SandboxStatusStarted,
		ContainerID: "ctr-probe-no-ip", ContainerIP: "", // no IP
		Runtime: models.RuntimeDocker,
		CPU:     1, MemoryMB: 256, DiskGB: 5,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	if _, err := svc.ExposePort(ctx, "sb-probe-no-ip", 8080, models.ExposedPortProtocolHTTP); err != nil {
		t.Fatalf("ExposePort: %v", err)
	}
	if probeCalls != 0 {
		t.Fatalf("probe calls = %d, want 0 when ContainerIP is empty", probeCalls)
	}
}

// TestExposePortSkipsProbeOnStoppedSandbox verifies that a stopped sandbox
// (e.g. being started lazily via serverless wake) does not trigger the probe.
func TestExposePortSkipsProbeOnStoppedSandbox(t *testing.T) {
	ctx := context.Background()
	var probeCalls int
	svc, st := newProbeSvc(t, func(_ context.Context, ip string, port int) error {
		probeCalls++
		return nil
	})

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-probe-stopped", Image: "alpine:3.20",
		Status:      models.SandboxStatusStopped, // not started
		ContainerID: "ctr-probe-stopped", ContainerIP: "10.0.0.12",
		Runtime: models.RuntimeDocker,
		CPU:     1, MemoryMB: 256, DiskGB: 5,
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	if _, err := svc.ExposePort(ctx, "sb-probe-stopped", 8080, models.ExposedPortProtocolHTTP); err != nil {
		t.Fatalf("ExposePort: %v", err)
	}
	if probeCalls != 0 {
		t.Fatalf("probe calls = %d, want 0 on stopped sandbox", probeCalls)
	}
}

// TestExposePortRejectedWhenPublicTrafficDisabled verifies that a sandbox
// created with allow_public_traffic=false cannot be exposed: ExposePort returns
// ErrPublicTrafficDisabled instead of installing a public route.
func TestExposePortRejectedWhenPublicTrafficDisabled(t *testing.T) {
	ctx := context.Background()
	svc, st := newProbeSvc(t, func(_ context.Context, _ string, _ int) error { return nil })

	now := time.Now().UTC()
	deny := false
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-no-public", Image: "alpine:3.20",
		Status:      models.SandboxStatusStarted,
		ContainerID: "ctr-no-public", ContainerIP: "10.0.0.20",
		Runtime: models.RuntimeDocker,
		CPU:     1, MemoryMB: 256, DiskGB: 5,
		AllowPublicTraffic: &deny,
		CreatedAt:          now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	_, err := svc.ExposePort(ctx, "sb-no-public", 8080, models.ExposedPortProtocolHTTP)
	if !errors.Is(err, ErrPublicTrafficDisabled) {
		t.Fatalf("ExposePort err = %v, want ErrPublicTrafficDisabled", err)
	}
}

// TestExposePortProceedsWhenProbeFailsAndLogsWarning verifies that a failing
// probe (port not yet bound) is non-fatal: the route is still installed and
// the error is surfaced only as a log warning, not as an ExposePort failure.
func TestExposePortProceedsWhenProbeFailsAndLogsWarning(t *testing.T) {
	ctx := context.Background()
	probeErr := errors.New("connection refused")
	var warnMessages []string
	logHandler := &captureWarnHandler{msgs: &warnMessages}

	svc, st := newProbeSvc(t, func(_ context.Context, ip string, port int) error {
		return probeErr
	})
	svc.logger = slog.New(logHandler)
	seedStartedSandboxAt(t, ctx, st, "sb-probe-fail", "10.0.0.13")

	_, err := svc.ExposePort(ctx, "sb-probe-fail", 8080, models.ExposedPortProtocolHTTP)
	if err != nil {
		t.Fatalf("ExposePort should succeed even when probe fails, got: %v", err)
	}

	got, err := st.Get(ctx, "sb-probe-fail")
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	if findExposure(got, 8080) == nil {
		t.Fatal("port 8080 should be recorded in store even when probe fails")
	}

	var found bool
	for _, msg := range warnMessages {
		if strings.Contains(msg, "not yet accepting") {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected a warn log about port not accepting; got: %v", warnMessages)
	}
}

// captureWarnHandler is a slog.Handler that collects Warn-level messages.
type captureWarnHandler struct {
	msgs *[]string
}

func (h *captureWarnHandler) Enabled(_ context.Context, lvl slog.Level) bool {
	return lvl >= slog.LevelWarn
}
func (h *captureWarnHandler) Handle(_ context.Context, r slog.Record) error {
	*h.msgs = append(*h.msgs, r.Message)
	return nil
}
func (h *captureWarnHandler) WithAttrs(_ []slog.Attr) slog.Handler {
	return &captureWarnHandler{msgs: h.msgs}
}
func (h *captureWarnHandler) WithGroup(_ string) slog.Handler { return h }

// ── Fix 3: createSandbox outer timeout ───────────────────────────────────────

// blockingRuntime is a runtime whose Create call blocks until ctx is cancelled.
// Used to exercise the SB_CREATE_TIMEOUT_SEC guard.
type blockingRuntime struct {
	recordingRuntime
}

func (r *blockingRuntime) Create(ctx context.Context, _ models.CreateSandboxRequest, sandboxID, _ string, _ []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestCreateSandboxTimeoutCancelsSlowCreate verifies that a createSandbox call
// exceeding SB_CREATE_TIMEOUT_SEC is cancelled with context.DeadlineExceeded
// rather than blocking indefinitely.
func TestCreateSandboxTimeoutCancelsSlowCreate(t *testing.T) {
	rt := &blockingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, &rt.recordingRuntime)
	svc.docker = rt
	svc.cfg.CreateSandboxTimeoutSeconds = 1 // 1-second ceiling
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})

	ctx := context.Background()
	start := time.Now()
	_, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      1,
		MemoryMB: 256,
		DiskGB:   5,
	})
	elapsed := time.Since(start)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("CreateSandbox error = %v, want context.DeadlineExceeded", err)
	}
	// Should fire in roughly 1 second — allow 3s for CI variance.
	if elapsed > 3*time.Second {
		t.Fatalf("CreateSandbox took %s, expected to cancel within ~1s", elapsed)
	}
}

// TestCreateSandboxZeroTimeoutDisablesGuard verifies that setting
// CreateSandboxTimeoutSeconds=0 disables the guard: a normally-fast create
// succeeds even when the config is zero.
func TestCreateSandboxZeroTimeoutDisablesGuard(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.CreateSandboxTimeoutSeconds = 0 // disabled
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})

	ctx := context.Background()
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      1,
		MemoryMB: 256,
		DiskGB:   5,
	})
	if err != nil {
		t.Fatalf("CreateSandbox with zero timeout failed: %v", err)
	}
	if resp == nil || resp.Sandbox.ID == "" {
		t.Fatal("CreateSandbox returned nil or empty sandbox")
	}
}

// TestCreateSandboxTimeoutDoesNotAffectFastCreates ensures the timeout guard
// has no effect when the create completes well within the window.
func TestCreateSandboxTimeoutDoesNotAffectFastCreates(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.cfg.CreateSandboxTimeoutSeconds = 60 // generous
	svc.caddy = caddy.New(config.Config{EnableCaddy: false, HTTPClientTimeout: time.Second})

	ctx := context.Background()
	resp, err := svc.CreateSandbox(ctx, models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      1,
		MemoryMB: 256,
		DiskGB:   5,
	})
	if err != nil {
		t.Fatalf("CreateSandbox failed: %v", err)
	}
	if resp == nil || resp.Sandbox.ID == "" {
		t.Fatal("CreateSandbox returned empty sandbox")
	}
}

// TestCreateSandboxNameConflictReturnsError verifies that creating two sandboxes
// with the same non-empty name fails on the second call. The HTTP-layer 409
// mapping is tested separately in pkg/api/apihttp.
func TestCreateSandboxNameConflictReturnsError(t *testing.T) {
	ctx := context.Background()
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)

	req := models.CreateSandboxRequest{
		Image: "alpine:3.20", CPU: 1, MemoryMB: 256, DiskGB: 5,
		Name: "my-unique-sandbox",
	}
	if _, err := svc.CreateSandbox(ctx, req); err != nil {
		t.Fatalf("first CreateSandbox: %v", err)
	}

	_, err := svc.CreateSandbox(ctx, req)
	if err == nil {
		t.Fatal("second CreateSandbox with the same name should fail")
	}
	if !errors.Is(err, storepkg.ErrSandboxNameConflict) {
		t.Fatalf("error = %v, want ErrSandboxNameConflict", err)
	}
}
