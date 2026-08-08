//go:build integration

package secrets

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// TestAWSKMSLiveRoundTrip is the live-AWS hook for D7. Skips unless
// SB_SECRET_AWS_KMS_KEY_ID (and standard AWS credentials) are present.
// Never runs under plain `make test` — gated by the integration build tag.
func TestAWSKMSLiveRoundTrip(t *testing.T) {
	keyID := os.Getenv("SB_SECRET_AWS_KMS_KEY_ID")
	if keyID == "" {
		t.Skip("SB_SECRET_AWS_KMS_KEY_ID not set; skipping live AWS KMS")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	w, err := NewAWSKMS(ctx, keyID)
	if err != nil {
		t.Fatalf("NewAWSKMS: %v", err)
	}
	if err := CanaryWrapUnwrap(ctx, w); err != nil {
		t.Fatalf("CanaryWrapUnwrap: %v", err)
	}

	p := NewKMSProvider(w, newMemBlobStore())
	h, err := p.Put(ctx, "sb-live-kms", Secrets{
		Registry: &models.RegistryAuth{Password: "live-secret"},
	}, []string{"node-a"})
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := p.Open(ctx, "sb-live-kms", h, "node-outsider")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if got.Registry == nil || got.Registry.Password != "live-secret" {
		t.Fatalf("registry = %+v", got.Registry)
	}
}
