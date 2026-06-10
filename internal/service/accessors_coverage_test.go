package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestTemplateReadPaths(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})

	// Empty store: ListTemplates returns no rows; GetTemplate not found.
	list, err := svc.ListTemplates(ctx)
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected no templates, got %d", len(list))
	}
	if _, err := svc.GetTemplate(ctx, "tpl-missing"); err == nil {
		t.Fatal("GetTemplate(missing) should error")
	}

	// Seed a template row via the store and read it back through the service.
	now := time.Now().UTC().Round(time.Second)
	if err := st.CreateTemplate(ctx, &models.Template{
		ID:        "tpl-cov",
		Image:     "ubuntu:22.04",
		Status:    models.TemplateStatusPending,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("CreateTemplate: %v", err)
	}
	got, err := svc.GetTemplate(ctx, "tpl-cov")
	if err != nil {
		t.Fatalf("GetTemplate: %v", err)
	}
	if got.ID != "tpl-cov" {
		t.Fatalf("GetTemplate = %+v", got)
	}
	list, err = svc.ListTemplates(ctx)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListTemplates = %v, %v", list, err)
	}
}

func TestPusherAccessors(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})

	// Nil reconcilers initially.
	if svc.SnapshotPushReconciler() != nil {
		t.Fatal("SnapshotPushReconciler should be nil before attach")
	}
	if svc.TemplateArtifactPushReconciler() != nil {
		t.Fatal("TemplateArtifactPushReconciler should be nil before attach")
	}

	// Nil pusher is ignored (no panic, stays nil).
	svc.AttachSnapshotPusher(nil, nil)
	svc.AttachTemplateArtifactPusher(nil, nil)
	if svc.SnapshotPushReconciler() != nil || svc.TemplateArtifactPushReconciler() != nil {
		t.Fatal("nil attach should leave reconcilers nil")
	}
}

func TestIngressAndCustomDomainDNS(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.AttachCluster(cluster.NewNoop("n1", "http://127.0.0.1:1", "sandbox.example.com"))

	// IngressDNSTarget surfaces the configured public host via the Noop.
	target := svc.IngressDNSTarget()
	_ = target // value shape varies; the call itself is what we cover.

	// Custom domains disabled in this config → ErrCustomDomainNotSupported.
	if _, err := svc.CustomDomainDNS(ctx, "whatever"); !errors.Is(err, ErrCustomDomainNotSupported) {
		t.Fatalf("CustomDomainDNS(disabled) = %v, want ErrCustomDomainNotSupported", err)
	}

	// Enable custom domains + a domain so the read path runs end to end.
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "sandbox.example.com"

	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID:           "sb-dns",
		Image:        "alpine:3.20",
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeDocker,
		CPU:          1,
		MemoryMB:     512,
		DiskGB:       5,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	// No attached domains → empty Records, no error.
	recs, err := svc.CustomDomainDNS(ctx, "sb-dns")
	if err != nil {
		t.Fatalf("CustomDomainDNS: %v", err)
	}
	if recs.Records == nil {
		t.Fatal("Records should be non-nil (stable [] JSON shape)")
	}

	// Missing sandbox → not found.
	if _, err := svc.CustomDomainDNS(ctx, "sb-missing"); err == nil {
		t.Fatal("CustomDomainDNS(missing) should error")
	}
}

func TestIngressAndCustomDomainDNSBranches(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	svc.AttachCluster(cluster.NewNoop("n1", "http://127.0.0.1:1", "sandbox.example.com"))
	svc.cfg.EnableCustomDomains = true
	svc.cfg.Domain = "sandbox.example.com"

	seedStartedSandbox(t, st, "sb-dns-branches")
	if err := st.AddCustomDomain(ctx, "sb-dns-branches", "api.sandbox.example.com", 0); err != nil {
		t.Fatalf("AddCustomDomain: %v", err)
	}
	recs, err := svc.CustomDomainDNS(ctx, "sb-dns-branches")
	if err != nil {
		t.Fatalf("CustomDomainDNS(branches): %v", err)
	}
	if len(recs.Records) == 0 {
		t.Fatal("expected non-empty DNS records for attached custom domain")
	}
	if recs.Target.Hostname == "" && len(recs.Target.IPs) == 0 {
		t.Fatal("expected ingress target to be preserved")
	}
}

func TestIngressInstalledVersion(t *testing.T) {
	// Package-level expvar-backed read; just ensure it returns without panic.
	_ = IngressInstalledVersion()
}

func TestCaddyCoalescerToggle(t *testing.T) {
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})

	// Stop without start is a safe no-op.
	svc.StopCaddyCoalescer()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartCaddyCoalescer(ctx)
	// Second start is idempotent.
	svc.StartCaddyCoalescer(ctx)
	svc.StopCaddyCoalescer()
}
