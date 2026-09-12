package docker

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCoverage95BuildImageLockedConcurrentDedup(t *testing.T) {
	var builds atomic.Int32
	c := &Client{
		streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			builds.Add(1)
			time.Sleep(50 * time.Millisecond)
			return textResponse(http.StatusOK, `{"stream":"ok"}`), nil
		})},
	}
	req := BuildImageRequest{Tag: "aerolvm-build/dedup:latest", DockerfileContent: "FROM scratch"}
	errCh := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { errCh <- c.BuildImage(context.Background(), req) }()
	}
	for i := 0; i < 2; i++ {
		if err := <-errCh; err != nil {
			t.Fatalf("BuildImage() = %v", err)
		}
	}
	if got := builds.Load(); got != 1 {
		t.Fatalf("build calls = %d, want 1 (deduped)", got)
	}
}

func TestCoverage95AssembleBuildContextNonZeroTrailer(t *testing.T) {
	extra := makeTar(t, map[string]string{"ctx.txt": "data"})
	out, err := assembleBuildContext("FROM scratch\n", extra)
	if err != nil {
		t.Fatal(err)
	}
	if len(out) == 0 {
		t.Fatal("expected non-empty tar")
	}
}

func TestCoverage95PushImageDecodeErrorDetail(t *testing.T) {
	validAuth := models.RegistryAuth{Username: "u", Password: "p", Server: "ghcr.io"}
	c := &Client{
		logger:     slog.Default(),
		httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) { return textResponse(http.StatusOK, "{}"), nil })},
		streamClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusOK, `{"errorDetail":{"message":"denied"}}`), nil
		})},
	}
	_, err := c.PushImage(context.Background(), PushImageRequest{
		SourceTag: "src:latest", DestRef: "ghcr.io/org/img:v1", Auth: validAuth,
	})
	if err == nil || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("PushImage() = %v", err)
	}
}
