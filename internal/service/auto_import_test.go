package service

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func validImportCfg(baseURL string) AutoImportConfig {
	return AutoImportConfig{
		Enabled:         true,
		HooksBaseURL:    baseURL,
		ClusterID:       "cl-prod-us-east",
		ClusterPAT:      "pat_xxxxxxxxxxxxxxxx",
		RetentionSuffix: "--idle-90d",
		RequestTimeout:  500 * time.Millisecond,
	}
}

func TestAutoImportConfig_ValidateDisabledAlwaysOK(t *testing.T) {
	if err := (AutoImportConfig{}).Validate(); err != nil {
		t.Fatalf("disabled config must validate clean: %v", err)
	}
}

func TestAutoImportConfig_ValidateRequiresFields(t *testing.T) {
	cases := map[string]AutoImportConfig{
		"no host":   {Enabled: true, ClusterID: "x", ClusterPAT: "y"},
		"no id":     {Enabled: true, HooksBaseURL: "https://x", ClusterPAT: "y"},
		"no pat":    {Enabled: true, HooksBaseURL: "https://x", ClusterID: "y"},
		"bad suffix":{Enabled: true, HooksBaseURL: "https://x", ClusterID: "y", ClusterPAT: "z", RetentionSuffix: "idle-90d"},
	}
	for name, cfg := range cases {
		t.Run(name, func(t *testing.T) {
			if err := cfg.Validate(); err == nil {
				t.Fatalf("expected validation error for %s", name)
			}
		})
	}
}

func TestNewAutoImporter_DisabledReturnsNilNil(t *testing.T) {
	imp, err := NewAutoImporter(AutoImportConfig{})
	if err != nil || imp != nil {
		t.Fatalf("disabled config must yield (nil, nil), got (%v, %v)", imp, err)
	}
}

func TestAutoImporter_ImportSuccess(t *testing.T) {
	var calls atomic.Int64
	var capturedBody importBody
	var capturedAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		capturedAuth = r.Header.Get("Authorization")
		if r.URL.Path != "/v1/internal/imports" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &capturedBody); err != nil {
			t.Errorf("invalid JSON body: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(importResponse{
			Status:      "imported",
			RegistryRef: "aocr.aerol.ai/cluster/cl-prod-us-east/_imported/ghcr.io/aerol-ai/sandbox:v1--idle-90d",
		})
	}))
	defer srv.Close()

	imp, err := NewAutoImporter(validImportCfg(srv.URL))
	if err != nil {
		t.Fatalf("NewAutoImporter: %v", err)
	}
	res, err := imp.Import(context.Background(), AutoImportRequest{
		UpstreamHost:   "ghcr.io",
		UpstreamRepo:   "aerol-ai/sandbox",
		UpstreamTag:    "v1",
		UpstreamDigest: "sha256:aabbccdd",
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if res.AlreadyPresent {
		t.Fatalf("expected fresh import, got AlreadyPresent=true")
	}
	if !strings.HasSuffix(res.RegistryRef, "--idle-90d") {
		t.Fatalf("registry_ref missing retention suffix: %s", res.RegistryRef)
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("calls = %d, want 1", got)
	}
	if capturedAuth != "Bearer pat_xxxxxxxxxxxxxxxx" {
		t.Fatalf("Authorization header: %q", capturedAuth)
	}
	if capturedBody.UpstreamHost != "ghcr.io" || capturedBody.UpstreamRepo != "aerol-ai/sandbox" ||
		capturedBody.UpstreamDigest != "sha256:aabbccdd" || capturedBody.ClusterID != "cl-prod-us-east" ||
		capturedBody.TargetTagSuffix != "--idle-90d" {
		t.Fatalf("request body mismatch: %+v", capturedBody)
	}
}

func TestAutoImporter_ImportAlreadyPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(importResponse{
			Status:      "already_present",
			RegistryRef: "aocr.aerol.ai/cluster/X/_imported/ghcr.io/foo/bar:v1--idle-90d",
		})
	}))
	defer srv.Close()

	imp, _ := NewAutoImporter(validImportCfg(srv.URL))
	res, err := imp.Import(context.Background(), AutoImportRequest{
		UpstreamHost: "ghcr.io", UpstreamRepo: "foo/bar", UpstreamDigest: "sha256:xx",
	})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}
	if !res.AlreadyPresent {
		t.Fatalf("expected AlreadyPresent=true for already_present status")
	}
}

func TestAutoImporter_RejectsMissingFields(t *testing.T) {
	imp, _ := NewAutoImporter(validImportCfg("http://unused"))
	cases := map[string]AutoImportRequest{
		"no host":   {UpstreamRepo: "foo/bar", UpstreamDigest: "sha256:x"},
		"no repo":   {UpstreamHost: "ghcr.io", UpstreamDigest: "sha256:x"},
		"no digest": {UpstreamHost: "ghcr.io", UpstreamRepo: "foo/bar"},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := imp.Import(context.Background(), req); err == nil {
				t.Fatalf("expected validation error")
			}
		})
	}
}

func TestAutoImporter_PropagatesHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	}))
	defer srv.Close()
	imp, _ := NewAutoImporter(validImportCfg(srv.URL))
	_, err := imp.Import(context.Background(), AutoImportRequest{
		UpstreamHost: "ghcr.io", UpstreamRepo: "foo/bar", UpstreamDigest: "sha256:x",
	})
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("expected 403 wrapped error, got %v", err)
	}
}

func TestAutoImporter_RejectsEmptyRegistryRef(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(importResponse{Status: "imported", RegistryRef: ""})
	}))
	defer srv.Close()
	imp, _ := NewAutoImporter(validImportCfg(srv.URL))
	if _, err := imp.Import(context.Background(), AutoImportRequest{
		UpstreamHost: "ghcr.io", UpstreamRepo: "foo/bar", UpstreamDigest: "sha256:x",
	}); err == nil {
		t.Fatalf("expected error on empty registry_ref")
	}
}

func TestAutoImporter_NilImporterReturnsError(t *testing.T) {
	var imp *AutoImporter
	if _, err := imp.Import(context.Background(), AutoImportRequest{
		UpstreamHost: "ghcr.io", UpstreamRepo: "foo/bar", UpstreamDigest: "sha256:x",
	}); err == nil {
		t.Fatalf("expected error from nil importer")
	}
}
