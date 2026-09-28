package service

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestHandleDuplicateStoreCreateMissWave21(t *testing.T) {
	ctx := context.Background()
	svc, _, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
	if _, err := svc.handleDuplicateStoreCreate(ctx, "missing-dup", models.ErrSandboxExists); !errors.Is(err, models.ErrSandboxExists) {
		t.Fatalf("err = %v", err)
	}
}
