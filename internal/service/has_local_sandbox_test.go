package service

import (
	"context"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// HasLocalSandbox decides, while a cluster node's placement view catches up
// after a restart, whether the router may serve a request locally. Only a
// definite miss may say false: a store error must reach the handler as that
// error, never become a guessed "absent".
func TestHasLocalSandbox(t *testing.T) {
	ctx := context.Background()
	svc, st, _ := newServiceRuntimeHarnessAllowStoreClose(t, &recordingRuntime{})
	now := time.Now().UTC()
	if err := st.Create(ctx, &models.Sandbox{
		ID: "sb-here", Image: "alpine", Status: models.SandboxStatusStarted, OwnerRef: "tenant-a",
		CreatedAt: now, UpdatedAt: now, LastActiveAt: now,
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Unscoped on purpose: the handler that serves the row applies scoping.
	if !svc.HasLocalSandbox(controlplane.ContextWithAccess(ctx, paymentsToken()), "sb-here") {
		t.Fatal("a held row must report true regardless of the caller's tenant")
	}
	if svc.HasLocalSandbox(ctx, "sb-elsewhere") {
		t.Fatal("a missing row must report false")
	}
	if svc.HasLocalSandbox(ctx, "  ") {
		t.Fatal("an empty id must report false")
	}
	var nilSvc *Service
	if nilSvc.HasLocalSandbox(ctx, "sb-here") {
		t.Fatal("a nil service holds nothing")
	}

	_ = st.Close()
	if !svc.HasLocalSandbox(ctx, "sb-elsewhere") {
		t.Fatal("a store error must not read as absent")
	}
}
