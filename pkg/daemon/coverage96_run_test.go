package daemon

import (
	"context"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// An OTLP exporter configured for a plaintext endpoint while a CA bundle is
// also supplied refuses to start. Both exporters must only warn: tracing and
// metrics are observability, not boot prerequisites.
func TestCov96RunOTELExporterStartFailuresAreNonFatal(t *testing.T) {
	paths := setBaseRunEnv(t)
	setNoDockerEnv(t, paths)
	t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", filepath.Join(paths.clusterTLSDir, "ca.crt"))
	t.Setenv("SB_OTEL_TRACES_ENABLED", "true")
	t.Setenv("SB_OTEL_TRACES_ENDPOINT", "http://127.0.0.1:1")
	t.Setenv("SB_OTEL_METRICS_ENABLED", "true")
	t.Setenv("SB_OTEL_METRICS_ENDPOINT", "http://127.0.0.1:1")

	err, logs := runCapturingLogs(t, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	for _, want := range []string{"failed to start otel trace exporter", "failed to start otel metrics exporter"} {
		if !strings.Contains(logs, want) {
			t.Errorf("log lacks %q", want)
		}
	}
}

// With the resident host off, SB_WASM_POOL_ENABLED wires the per-sandbox warm
// pool, and Run owns closing it on shutdown.
func TestCov96RunWasmWarmPoolClosedOnShutdown(t *testing.T) {
	paths := setBaseRunEnv(t)
	setNoDockerEnv(t, paths)
	wasmRun := filepath.Join(paths.rootDir, "wasm-run")
	wasmModules := filepath.Join(paths.rootDir, "wasm-modules")
	for _, dir := range []string{wasmRun, wasmModules} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("SB_ENABLE_WASM", "true")
	t.Setenv("SB_WASM_RUN_DIR", wasmRun)
	t.Setenv("SB_WASM_MODULES_DIR", wasmModules)
	t.Setenv("SB_WASM_RESIDENT_HOST_ENABLED", "false")
	t.Setenv("SB_WASM_POOL_ENABLED", "true")
	t.Setenv("SB_WASM_POOL_DEPTH_DEFAULT", "1")
	t.Setenv("SB_WASM_STANDARD_MODULES", "")
	// wireWasmRuntime exports these to the process env for worker
	// subprocesses; t.Setenv restores them after the test.
	t.Setenv("AEROL_WASM_ENGINE", "")
	t.Setenv("AEROL_WASM_COMPILE_CACHE_DIR", "")

	err, logs := runCapturingLogs(t, 500*time.Millisecond)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if !strings.Contains(logs, "wasm warm pool enabled") {
		t.Fatal("warm pool was not wired with the resident host disabled")
	}
}

func cov96FreeLoopbackPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

func cov96DialUntil(addr string, deadline time.Time) net.Conn {
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			return c
		}
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

// A client that connected but never sent a request keeps both listeners from
// going quiet; with a 1ns shutdown budget Shutdown returns the deadline error,
// which Run must log rather than turn into a failed exit.
func TestCov96RunShutdownDeadlineExceededIsLogged(t *testing.T) {
	// The ports are picked, released, then bound by Run; a collision with an
	// unrelated process just costs an attempt.
	var lastLogs string
	for attempt := 0; attempt < 3; attempt++ {
		ok, logs := cov96RunWithHeldConnections(t)
		if ok {
			return
		}
		lastLogs = logs
	}
	t.Fatalf("shutdown deadline never reported; last log:\n%s", lastLogs)
}

func cov96RunWithHeldConnections(t *testing.T) (bool, string) {
	t.Helper()
	paths := setBaseRunEnv(t)
	setNoDockerEnv(t, paths)
	apiPort := cov96FreeLoopbackPort(t)
	ingressAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cov96FreeLoopbackPort(t)))
	t.Setenv("SB_API_PORT", strconv.Itoa(apiPort))
	t.Setenv("SB_INTERNAL_INGRESS_ADDR", ingressAddr)
	t.Setenv("SB_SHUTDOWN_TIMEOUT", "1ns")
	t.Setenv("SB_ENABLE_CADDY", "true")
	t.Setenv("SB_CADDY_ADMIN_URL", "http://127.0.0.1:1")
	t.Setenv("SB_ENABLE_CUSTOM_DOMAINS", "true")
	t.Setenv("SB_DOMAIN", "example.test")

	var buf syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- Run(ctx, slog.New(slog.NewTextHandler(&buf, nil)), nil) }()

	deadline := time.Now().Add(10 * time.Second)
	apiConn := cov96DialUntil(net.JoinHostPort("127.0.0.1", strconv.Itoa(apiPort)), deadline)
	ingressConn := cov96DialUntil(ingressAddr, deadline)
	defer func() {
		for _, c := range []net.Conn{apiConn, ingressConn} {
			if c != nil {
				_ = c.Close()
			}
		}
	}()
	// Let both servers accept and start tracking the idle connections.
	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	logs := buf.String()
	ok := apiConn != nil && ingressConn != nil &&
		strings.Contains(logs, "graceful shutdown failed") &&
		strings.Contains(logs, "ingress proxy graceful shutdown failed")
	return ok, logs
}
