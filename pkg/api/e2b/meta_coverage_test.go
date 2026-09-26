package e2b

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestSandboxMetaFromNativeNilTagsAndNetworkDefaults(t *testing.T) {
	sb := &models.Sandbox{Tags: nil, NetworkBlockAll: false}
	meta := sandboxMetaFromNative(sb, compatBlob{NetworkAllowOut: []string{""}})
	if meta.Metadata == nil || len(meta.Metadata) != 0 {
		t.Fatalf("metadata = %v", meta.Metadata)
	}
	if len(meta.NetworkAllowOut) != 0 {
		t.Fatalf("network allow out = %v", meta.NetworkAllowOut)
	}
	if meta.AllowInternetAccess == nil || !*meta.AllowInternetAccess {
		t.Fatalf("allow internet = %v", meta.AllowInternetAccess)
	}
}

func TestSandboxMetaCoverage95(t *testing.T) {
	sb := &models.Sandbox{
		Image:           "img",
		Tags:            nil,
		NetworkBlockAll: true,
		CreatedAt:       time.Now().Add(-30 * time.Second),
		Lifecycle:       models.Lifecycle{StopAtAge: 60 * time.Second},
	}
	meta := sandboxMetaFromNative(sb, compatBlob{Secure: true, OnTimeout: "kill"})
	if meta.Metadata == nil || len(meta.Metadata) != 0 {
		t.Fatalf("metadata = %v, want empty map", meta.Metadata)
	}
	if meta.AllowInternetAccess == nil || *meta.AllowInternetAccess {
		t.Fatalf("AllowInternetAccess = %v, want false", meta.AllowInternetAccess)
	}

	_, err := sandboxMetaFromState(&models.SandboxCompatState{StateJSON: "{bad"}, sb)
	if err == nil {
		t.Fatal("expected unmarshal error")
	}

	stateJSON, err := sandboxMetaToState(sandboxMeta{OnTimeout: "pause", Secure: true})
	if err != nil || stateJSON == "" {
		t.Fatalf("stateJSON = %q err=%v", stateJSON, err)
	}
}

func TestSandboxMetaFromNativeDestroyAtAgeBranch(t *testing.T) {
	sb := &models.Sandbox{
		CreatedAt: time.Now().Add(-5 * time.Second),
		Lifecycle: models.Lifecycle{DestroyAtAge: 30 * time.Second},
	}
	meta := sandboxMetaFromNative(sb, compatBlob{Secure: true, OnTimeout: "kill"})
	if meta.TimeoutSeconds <= 0 {
		t.Fatalf("expected positive timeout from destroy-at-age, got %d", meta.TimeoutSeconds)
	}
}

func TestCreateRequestFingerprintAndMetadataHelpers(t *testing.T) {
	fp, err := createRequestFingerprint("", "base", models.CreateSandboxRequest{Image: "ubuntu:22.04"}, sandboxMeta{
		TemplateID: "base", TimeoutSeconds: 120, OnTimeout: "kill",
	})
	if err != nil || fp == "" {
		t.Fatalf("fingerprint = %q err=%v", fp, err)
	}
	if got := sandboxIDFromFingerprint(fp); got == "" {
		t.Fatal("expected deterministic sandbox id")
	}
	filter, err := parseMetadataFilter("env=prod")
	if err != nil || filter["env"] != "prod" {
		t.Fatalf("filter = %v err=%v", filter, err)
	}
}

func TestSandboxMetaFromNativeNilNetworkSliceDefaults(t *testing.T) {
	meta := sandboxMetaFromNative(&models.Sandbox{Tags: map[string]string{"k": "v"}}, compatBlob{
		Secure:    true,
		OnTimeout: "kill",
	})
	if meta.NetworkAllowOut == nil || meta.NetworkDenyOut == nil {
		t.Fatalf("expected non-nil empty network slices, got allow=%v deny=%v", meta.NetworkAllowOut, meta.NetworkDenyOut)
	}
	if len(meta.NetworkAllowOut) != 0 || len(meta.NetworkDenyOut) != 0 {
		t.Fatalf("expected empty network slices")
	}
	if meta.Metadata == nil || meta.Metadata["k"] != "v" {
		t.Fatalf("metadata = %v", meta.Metadata)
	}
}

func TestResolveTemplateCanonicalSnapshotNameCoverage95(t *testing.T) {
	svc, st, _ := newE2BHandlerTestEnv(t)
	ctx := context.Background()
	if err := st.CreateSnapshot(ctx, &models.SandboxSnapshot{Name: "tpl-canonical:default", CreatedAt: time.Now()}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	h := newHandlers(Deps{Service: svc})
	img, _, err := h.resolveTemplate(ctx, "tpl-canonical")
	if err != nil || img != "tpl-canonical:default" {
		t.Fatalf("resolveTemplate = %q err=%v", img, err)
	}
}

func TestSandboxMetaFromNativeStopAtAgeCoverage95(t *testing.T) {
	now := time.Now().UTC().Add(-time.Minute)
	sb := &models.Sandbox{
		Image: "img", CreatedAt: now,
		Lifecycle: models.Lifecycle{StopAtAge: 10 * time.Minute},
	}
	meta := sandboxMetaFromNative(sb, compatBlob{OnTimeout: "kill"})
	if meta.TimeoutSeconds <= 0 || meta.OnTimeout != "pause" {
		t.Fatalf("meta = %+v", meta)
	}
}
