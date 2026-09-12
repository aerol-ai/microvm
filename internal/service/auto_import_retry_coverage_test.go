package service

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestAutoImportRequestFromSpecWave16(t *testing.T) {
	_, ok := autoImportRequestFromSpec(nil)
	if ok {
		t.Fatal("nil")
	}
	_, ok = autoImportRequestFromSpec(&models.CreateSandboxRequest{})
	if ok {
		t.Fatal("no failover")
	}
	_, ok = autoImportRequestFromSpec(&models.CreateSandboxRequest{
		Failover:              &models.Failover{Policy: models.FailoverPolicyRecreate},
		ImageDistributionMode: models.ImageDistributionAOCRImported,
	})
	if ok {
		t.Fatal("already imported")
	}
	_, ok = autoImportRequestFromSpec(&models.CreateSandboxRequest{
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	})
	if ok {
		t.Fatal("no digest")
	}
	_, ok = autoImportRequestFromSpec(&models.CreateSandboxRequest{
		Failover:    &models.Failover{Policy: models.FailoverPolicyRecreate},
		ImageDigest: "sha256:abc",
		Image:       "library/redis",
	})
	if ok {
		t.Fatal("no host")
	}
	req, ok := autoImportRequestFromSpec(&models.CreateSandboxRequest{
		Failover:         &models.Failover{Policy: models.FailoverPolicyRecreate},
		ImageDigest:      "sha256:abc",
		ImageRegistryRef: "ghcr.io/org/app:latest",
	})
	if !ok || req.UpstreamHost != "ghcr.io" {
		t.Fatalf("got %+v ok=%v", req, ok)
	}
	_, _, _ = parseUpstreamFromRegistryRef("", "localhost/foo/bar:baz")
	_, _, _ = parseUpstreamFromRegistryRef("bad", "")
}

func TestAutoImportRetryFlagClearFailWave26(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(importResponse{
			Status: "imported", RegistryRef: "aocr.test/x:1",
		})
	}))
	t.Cleanup(srv.Close)

	fs := newFakeStore()
	fs.seed("sb-ai", true)
	fs.setErr = errors.New("flag clear boom")
	imp, err := NewAutoImporter(validImportCfg(srv.URL))
	if err != nil || imp == nil {
		t.Fatalf("importer: %v", err)
	}
	r := NewAutoImportReconciler(imp, fs, &fakeSpecResolver{specs: map[string]*models.CreateSandboxRequest{
		"sb-ai": eligibleSpec(),
	}}, slog.New(slog.NewTextHandler(io.Discard, nil)), 1)
	got := r.retryOne(context.Background(), "sb-ai")
	if got != retryFailed {
		t.Fatalf("got %v want retryFailed", got)
	}
}
