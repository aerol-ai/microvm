package microvm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

func TestClientAndSandboxWrappers(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", Image: "ubuntu:22.04", Status: models.SandboxStatusStarted})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes":
			_ = json.NewEncoder(w).Encode([]models.Sandbox{{ID: "sb1", Image: "ubuntu:22.04", Status: models.SandboxStatusStarted}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/mounts":
			_ = json.NewEncoder(w).Encode(map[string]any{"mounts": []models.MountSpecRedacted{{Type: models.MountTypeS3, Target: "/workspace", Source: "bucket/path"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/network/usage":
			_ = json.NewEncoder(w).Encode(models.NetworkUsage{SandboxID: "sb1", BytesIn: 10, BytesOut: 20})
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/sandboxes/sb1/network/limits":
			_ = json.NewEncoder(w).Encode(models.NetworkUsage{SandboxID: "sb1", BytesInLimit: 100})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/start":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", Status: models.SandboxStatusStarted})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/stop":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", Status: models.SandboxStatusStopped})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sandboxes/sb1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/resize":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", CPU: 2})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/sandboxes/sb1/lifecycle":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", Lifecycle: models.Lifecycle{StopIfIdleFor: time.Minute}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/admin/reconcile":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/ingress/dns":
			_ = json.NewEncoder(w).Encode(models.IngressTarget{Source: "hostname", Hostname: "example.test"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/toolbox/process/execute":
			_ = json.NewEncoder(w).Encode(sdktypes.ExecResult{ExitCode: 0})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/toolbox/files/upload":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/toolbox/files/download":
			_, _ = w.Write([]byte("file-data"))
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/toolbox/clone-generation":
			_ = json.NewEncoder(w).Encode(map[string]any{"generation": "2d0d8c69", "resumed_at": 1700000000000000000})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/ports/8080":
			_ = json.NewEncoder(w).Encode(models.ExposePortResponse{Protocol: "http", PublicURL: "https://example.test"})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sandboxes/sb1/ports/8080":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/custom-domains":
			_ = json.NewEncoder(w).Encode(map[string]any{"custom_domains": []models.CustomDomain{{Hostname: "api.example.test"}}})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sandboxes/sb1/custom-domains/api.example.test":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/custom-domains":
			_ = json.NewEncoder(w).Encode(map[string]any{"custom_domains": []models.CustomDomain{{Hostname: "api.example.test"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/custom-domains/dns":
			_ = json.NewEncoder(w).Encode(models.CustomDomainDNSRecords{})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/snapshot":
			_ = json.NewEncoder(w).Encode(models.SandboxSnapshot{Name: "snap-1", CreatedAt: now})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client, err := NewClientWithConfig(&sdktypes.MicroVMConfig{PATToken: "pat", APIUrl: server.URL})
	if err != nil {
		t.Fatalf("NewClientWithConfig() error = %v", err)
	}

	if _, err := client.List(ctx); err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if _, err := client.Get(ctx, "sb1"); err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if _, err := client.Mounts(ctx, "sb1"); err != nil {
		t.Fatalf("Mounts() error = %v", err)
	}
	if gen, err := client.CloneGeneration(ctx, "sb1"); err != nil {
		t.Fatalf("CloneGeneration() error = %v", err)
	} else if gen.Generation != "2d0d8c69" || gen.ResumedAt != 1700000000000000000 {
		t.Fatalf("CloneGeneration() = %+v, want {2d0d8c69 1700000000000000000}", gen)
	}
	if _, err := client.GetNetworkUsage(ctx, "sb1"); err != nil {
		t.Fatalf("GetNetworkUsage() error = %v", err)
	}
	limit := int64(100)
	if _, err := client.SetNetworkLimits(ctx, "sb1", sdktypes.SetNetworkLimitsOptions{NetworkBytesInLimit: &limit}); err != nil {
		t.Fatalf("SetNetworkLimits() error = %v", err)
	}
	if _, err := client.Start(ctx, "sb1"); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	if _, err := client.Stop(ctx, "sb1"); err != nil {
		t.Fatalf("Stop() error = %v", err)
	}
	if err := client.Destroy(ctx, "sb1"); err != nil {
		t.Fatalf("Destroy() error = %v", err)
	}
	if _, err := client.Resize(ctx, "sb1", sdktypes.ResizeSandboxOptions{CPU: 2}); err != nil {
		t.Fatalf("Resize() error = %v", err)
	}
	if _, err := client.UpdateLifecycle(ctx, "sb1", sdktypes.Lifecycle{StopIfIdleFor: time.Minute}); err != nil {
		t.Fatalf("UpdateLifecycle() error = %v", err)
	}
	if err := client.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if _, err := client.Health(ctx); err != nil {
		t.Fatalf("Health() error = %v", err)
	}
	if _, err := client.DNSTarget(ctx); err != nil {
		t.Fatalf("DNSTarget() error = %v", err)
	}

	sb := &Sandbox{Sandbox: sdktypes.Sandbox{ID: "sb1"}, client: client}
	if err := sb.Refresh(ctx); err != nil {
		t.Fatalf("Sandbox.Refresh() error = %v", err)
	}
	if _, err := sb.Exec(ctx, sdktypes.ExecRequest{Command: "echo hi"}); err != nil {
		t.Fatalf("Sandbox.Exec() error = %v", err)
	}
	if _, err := sb.ExecCommand(ctx, "echo hi"); err != nil {
		t.Fatalf("Sandbox.ExecCommand() error = %v", err)
	}
	if err := sb.UploadFile(ctx, "/tmp/f.txt", []byte("x")); err != nil {
		t.Fatalf("Sandbox.UploadFile() error = %v", err)
	}
	if _, err := sb.DownloadFile(ctx, "/tmp/f.txt"); err != nil {
		t.Fatalf("Sandbox.DownloadFile() error = %v", err)
	}
	if _, err := sb.ExposePort(ctx, 8080, WithProtocol(sdktypes.ExposeProtocolHTTP)); err != nil {
		t.Fatalf("Sandbox.ExposePort() error = %v", err)
	}
	if err := sb.UnexposePort(ctx, 8080); err != nil {
		t.Fatalf("Sandbox.UnexposePort() error = %v", err)
	}
	if _, err := sb.AddCustomDomain(ctx, "api.example.test", WithTargetPort(3000)); err != nil {
		t.Fatalf("Sandbox.AddCustomDomain() error = %v", err)
	}
	if err := sb.RemoveCustomDomain(ctx, "api.example.test"); err != nil {
		t.Fatalf("Sandbox.RemoveCustomDomain() error = %v", err)
	}
	if _, err := sb.ListCustomDomains(ctx); err != nil {
		t.Fatalf("Sandbox.ListCustomDomains() error = %v", err)
	}
	if _, err := sb.CustomDomainDNS(ctx); err != nil {
		t.Fatalf("Sandbox.CustomDomainDNS() error = %v", err)
	}
	if _, err := sb.CreateSnapshot(ctx, "snap-1"); err != nil {
		t.Fatalf("Sandbox.CreateSnapshot() error = %v", err)
	}
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("Sandbox.Start() error = %v", err)
	}
	if err := sb.Stop(ctx); err != nil {
		t.Fatalf("Sandbox.Stop() error = %v", err)
	}
	if err := sb.Resize(ctx, sdktypes.ResizeSandboxOptions{CPU: 2}); err != nil {
		t.Fatalf("Sandbox.Resize() error = %v", err)
	}
	if _, err := sb.GetNetworkUsage(ctx); err != nil {
		t.Fatalf("Sandbox.GetNetworkUsage() error = %v", err)
	}
	if _, err := sb.SetNetworkLimits(ctx, sdktypes.SetNetworkLimitsOptions{NetworkBytesInLimit: &limit}); err != nil {
		t.Fatalf("Sandbox.SetNetworkLimits() error = %v", err)
	}
	if err := sb.UpdateLifecycle(ctx, sdktypes.Lifecycle{StopIfIdleFor: time.Minute}); err != nil {
		t.Fatalf("Sandbox.UpdateLifecycle() error = %v", err)
	}
	if err := sb.Destroy(ctx); err != nil {
		t.Fatalf("Sandbox.Destroy() error = %v", err)
	}
}
