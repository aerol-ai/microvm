package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestInstallTLSWakeAndDirectFailWave10(t *testing.T) {
	ctx := context.Background()
	failServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		http.Error(w, "fail", http.StatusInternalServerError)
	}))
	t.Cleanup(failServer.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCaddy = true
	svc.cfg.EnableServerless = true
	svc.cfg.Domain = "sandbox.example.com"
	svc.cfg.L4TLSListen = "127.0.0.1:9443"
	svc.cfg.InternalL4WakeAddr = "127.0.0.1:21214"
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, Domain: "sandbox.example.com",
		CaddyAdminURL: failServer.URL, CaddyServerID: "srv0",
		L4TLSListen: "127.0.0.1:9443", HTTPClientTimeout: time.Second,
	})
	svc.l4Ready.Store(true)

	direct := &models.Sandbox{
		ID: "sb-tls-d10", Status: models.SandboxStatusStarted, ContainerIP: "10.0.0.2",
	}
	if err := svc.installTLSPortRoute(ctx, direct, 8443); err == nil {
		t.Fatal("expected direct TLS upsert failure")
	}

	wake := &models.Sandbox{
		ID: "sb-tls-w10", Status: models.SandboxStatusStopped, WakeArmed: true,
		Lifecycle: models.Lifecycle{Serverless: true, StopIfIdleFor: time.Minute},
	}
	if err := svc.installTLSPortRoute(ctx, wake, 8443); err == nil {
		t.Fatal("expected wake TLS upsert failure")
	}
}
