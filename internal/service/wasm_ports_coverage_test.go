package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestWasmSyncGuestListenWarnWave21(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	svc.SetWasmRuntime(wasmPortsSyncErrRuntime{syncErr: errors.New("sync boom")})
	svc.syncWasmAllowedPorts(ctx, &models.Sandbox{
		ID: "sb-sync", Runtime: models.RuntimeWasm,
		ExposedPorts: []models.ExposedPort{{Port: 8080}},
	})
}

func TestWasmHTTPRouteWakeDeleteWave22(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableWasm = true
	svc.cfg.EnableServerless = true
	svc.cfg.HTTPWakeDirectBypassEnabled = false // wake always for serverless
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.InternalIngressAddr = "127.0.0.1:21222"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	svc.SetWasmRuntime(&wasmPortsRuntime{recordingRuntime: &recordingRuntime{}})
	sb := &models.Sandbox{
		ID: "wasm-wake22", Runtime: models.RuntimeWasm, Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installWasmHTTPPortRoute(ctx, sb, 8080); err != nil {
		t.Fatalf("wake: %v", err)
	}
}
