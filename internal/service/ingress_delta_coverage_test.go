package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/caddy"
)

func TestGCUnexpectedIngressDeleteErrorsWave21(t *testing.T) {
	ctx := context.Background()
	fake := newGCCaddyFake()
	fake.httpRouteIDs["sandbox-zombie21"] = struct{}{}
	fake.l4TCPServerIDs["tcp-port-39991"] = struct{}{}
	fake.l4TLSRouteIDs["sandbox-zombie21-port-8443-tls"] = struct{}{}
	base := fake.handler(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			http.Error(w, "delete boom", http.StatusInternalServerError)
			return
		}
		base.ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)

	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.EnableCluster = true
	svc.cfg.EnableCaddy = true
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	if err := svc.gcUnexpectedClusterIngressRoutes(ctx, map[string]ingressRouteIntent{}); err == nil {
		t.Fatal("expected firstErr from delete failures")
	}
}

func TestConfigDomainEmptyApplyInFluxPortWave22(t *testing.T) {
	ctx := context.Background()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusOK)
			return
		}
		http.Error(w, "up", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.cfg.Domain = ""
	svc.cfg.EnableCaddy = true
	svc.caddy = caddy.New(config.Config{
		EnableCaddy: true, CaddyAdminURL: server.URL, CaddyServerID: "srv0", HTTPClientTimeout: time.Second,
	})
	_ = svc.applyInFluxPortRoute(ctx, cluster.Placement{SandboxID: "sb"}, 80)
	_ = svc.applyInFluxSandboxRoute(ctx, cluster.Placement{SandboxID: "sb"})
}
