package apiclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestClientAndSandboxWrappers(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", Image: "ubuntu:22.04", Status: models.SandboxStatusStarted})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/start":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", Image: "ubuntu:22.04", Status: models.SandboxStatusStarted})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/stop":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", Image: "ubuntu:22.04", Status: models.SandboxStatusStopped})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sandboxes/sb1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/admin/reconcile":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/resize":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", CPU: 2, MemoryMB: 1024})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/sandboxes/sb1/lifecycle":
			_ = json.NewEncoder(w).Encode(models.Sandbox{ID: "sb1", Lifecycle: models.Lifecycle{StopIfIdleFor: time.Minute}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/mounts":
			_ = json.NewEncoder(w).Encode(map[string]any{"mounts": []models.MountSpecRedacted{{Type: models.MountTypeS3, Target: "/workspace", Source: "bucket/path"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/sandboxes/sb1/toolbox/files/download":
			_, _ = w.Write([]byte("payload"))
		case r.Method == http.MethodPost && r.URL.Path == "/v1/sandboxes/sb1/ports/8080":
			_ = json.NewEncoder(w).Encode(ExposeResult{Protocol: "http", PublicURL: "https://example.local"})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/sandboxes/sb1/ports/8080":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/templates":
			_ = json.NewEncoder(w).Encode(models.Template{ID: "tpl-1", Image: "img:1", Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/templates":
			_ = json.NewEncoder(w).Encode([]models.Template{{ID: "tpl-1", Image: "img:1", Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/templates/tpl-1":
			_ = json.NewEncoder(w).Encode(models.Template{ID: "tpl-1", Image: "img:1", Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/templates/tpl-1":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/templates/tpl-1/rebuild":
			_ = json.NewEncoder(w).Encode(models.Template{ID: "tpl-1", Image: "img:1", Status: models.TemplateStatusPending, CreatedAt: now, UpdatedAt: now})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/images/build":
			_ = json.NewEncoder(w).Encode(map[string]string{"image": "img:built"})
		default:
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	client := NewClient(server.URL, ClientOptions{PATToken: "pat", HTTPClient: server.Client()})

	if client.versionedURL() != "/v1" {
		t.Fatalf("versionedURL = %q, want /v1", client.versionedURL())
	}

	if _, err := client.Get(ctx, "sb1"); err != nil {
		t.Fatalf("Get() error = %v", err)
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
	if err := client.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile() error = %v", err)
	}
	if _, err := client.Resize(ctx, "sb1", ResizeOptions{CPU: 2, MemoryMB: 1024}); err != nil {
		t.Fatalf("Resize() error = %v", err)
	}
	if _, err := client.UpdateLifecycle(ctx, "sb1", models.Lifecycle{StopIfIdleFor: time.Minute}); err != nil {
		t.Fatalf("UpdateLifecycle() error = %v", err)
	}
	if mounts, err := client.Mounts(ctx, "sb1"); err != nil || len(mounts) != 1 {
		t.Fatalf("Mounts() got len=%d err=%v", len(mounts), err)
	}
	if data, err := client.DownloadFile(ctx, "sb1", "/workspace/file.txt"); err != nil || string(data) != "payload" {
		t.Fatalf("DownloadFile() got=%q err=%v", string(data), err)
	}
	if _, err := client.ExposePort(ctx, "sb1", 8080, ""); err != nil {
		t.Fatalf("ExposePort() error = %v", err)
	}
	if err := client.UnexposePort(ctx, "sb1", 8080); err != nil {
		t.Fatalf("UnexposePort() error = %v", err)
	}
	if _, err := client.CreateTemplate(ctx, models.CreateTemplateRequest{Image: "img:1"}); err != nil {
		t.Fatalf("CreateTemplate() error = %v", err)
	}
	if _, err := client.ListTemplates(ctx); err != nil {
		t.Fatalf("ListTemplates() error = %v", err)
	}
	if _, err := client.GetTemplate(ctx, "tpl-1"); err != nil {
		t.Fatalf("GetTemplate() error = %v", err)
	}
	if err := client.DeleteTemplate(ctx, "tpl-1"); err != nil {
		t.Fatalf("DeleteTemplate() error = %v", err)
	}
	if _, err := client.RebuildTemplate(ctx, "tpl-1"); err != nil {
		t.Fatalf("RebuildTemplate() error = %v", err)
	}
	if img, err := client.BuildImage(ctx, "FROM alpine"); err != nil || img != "img:built" {
		t.Fatalf("BuildImage() got=%q err=%v", img, err)
	}

	sb := &Sandbox{Sandbox: models.Sandbox{ID: "sb1"}, client: client}
	if err := sb.Refresh(ctx); err != nil {
		t.Fatalf("Sandbox.Refresh() error = %v", err)
	}
	if err := sb.Start(ctx); err != nil {
		t.Fatalf("Sandbox.Start() error = %v", err)
	}
	if err := sb.Stop(ctx); err != nil {
		t.Fatalf("Sandbox.Stop() error = %v", err)
	}
	if err := sb.Resize(ctx, ResizeOptions{CPU: 2}); err != nil {
		t.Fatalf("Sandbox.Resize() error = %v", err)
	}
	if err := sb.UpdateLifecycle(ctx, models.Lifecycle{StopIfIdleFor: time.Minute}); err != nil {
		t.Fatalf("Sandbox.UpdateLifecycle() error = %v", err)
	}
	if _, err := sb.DownloadFile(ctx, "/workspace/file.txt"); err != nil {
		t.Fatalf("Sandbox.DownloadFile() error = %v", err)
	}
	if _, err := sb.ExposePort(ctx, 8080, ""); err != nil {
		t.Fatalf("Sandbox.ExposePort() error = %v", err)
	}
	if err := sb.Destroy(ctx); err != nil {
		t.Fatalf("Sandbox.Destroy() error = %v", err)
	}
}

func TestBuildImageWithPushValidation(t *testing.T) {
	ctx := context.Background()
	client := NewClient("http://example.invalid", ClientOptions{})

	if _, err := client.BuildImageWithPush(ctx, "", nil); err == nil {
		t.Fatalf("expected error for empty dockerfile")
	}
	if _, err := client.BuildImageWithPush(ctx, "FROM alpine", &BuildImagePushSpec{Username: "u", Password: "p"}); err == nil {
		t.Fatalf("expected error for missing push registry")
	}
	if _, err := client.BuildImageWithPush(ctx, "FROM alpine", &BuildImagePushSpec{Registry: "r"}); err == nil {
		t.Fatalf("expected error for missing push credentials")
	}
}
