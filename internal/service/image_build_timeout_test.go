package service

import (
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
)

// ImageBuildTimeout reports SB_IMAGE_BUILD_TIMEOUT as configured, and 0 for
// a nil service, so a caller can size a forwarded build's limit from it.
func TestImageBuildTimeout(t *testing.T) {
	if got := (*Service)(nil).ImageBuildTimeout(); got != 0 {
		t.Fatalf("nil service = %v, want 0", got)
	}
	for _, want := range []time.Duration{0, 10 * time.Minute, 90 * time.Second} {
		svc := &Service{cfg: config.Config{ImageBuildTimeout: want}}
		if got := svc.ImageBuildTimeout(); got != want {
			t.Fatalf("ImageBuildTimeout() = %v, want %v", got, want)
		}
	}
}
