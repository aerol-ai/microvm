package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/capacity"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func dockerPoolServiceHarness(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	admitter := capacity.New(
		capacity.HostInfo{CPUCores: 4, MemoryTotalMB: 4096},
		capacity.Limits{CPUReservationRatio: 1, MemoryReservationRatio: 1},
		nil,
	)
	svc := &Service{store: st, admitter: admitter, cfg: config.Config{Runtime: models.RuntimeDocker}}
	return svc, st
}

func TestReleaseAdoptedParkReservation(t *testing.T) {
	svc, _ := dockerPoolServiceHarness(t)
	admitter := svc.admitter
	shape := capacity.Request{CPU: 1, MemoryMB: 512, Runtime: models.RuntimeDocker}
	if err := admitter.Admit(capacity.ParkReservationID("park-1"), shape); err != nil {
		t.Fatal(err)
	}
	svc.releaseAdoptedParkReservation(&models.SandboxRuntimeState{AdoptedParkID: "park-1"})
	if snap := admitter.Snapshot(); snap.SandboxesActive != 0 {
		t.Fatalf("active = %d", snap.SandboxesActive)
	}
	svc.releaseAdoptedParkReservation(nil)
	svc.releaseAdoptedParkReservation(&models.SandboxRuntimeState{})
}

func TestHandleDuplicateCreateAfterRuntime(t *testing.T) {
	svc, st := dockerPoolServiceHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sb := &models.Sandbox{ID: "sb-dup", Image: "i", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.handleDuplicateCreateAfterRuntime(ctx, "sb-dup", docker.ErrSandboxContainerExists)
	if err != nil || resp == nil || resp.Sandbox.ID != "sb-dup" {
		t.Fatalf("resp = %+v err = %v", resp, err)
	}

	_, err = svc.handleDuplicateCreateAfterRuntime(ctx, "missing", docker.ErrSandboxContainerExists)
	if !errors.Is(err, models.ErrSandboxExists) {
		t.Fatalf("err = %v", err)
	}
	_, err = svc.handleDuplicateCreateAfterRuntime(ctx, "sb-dup", errors.New("other"))
	if err == nil {
		t.Fatal("expected passthrough error")
	}
}

func TestHandleDuplicateStoreCreate(t *testing.T) {
	svc, st := dockerPoolServiceHarness(t)
	ctx := context.Background()
	now := time.Now().UTC()
	sb := &models.Sandbox{ID: "sb-store", Image: "i", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now}
	if err := st.Create(ctx, sb); err != nil {
		t.Fatal(err)
	}

	resp, err := svc.handleDuplicateStoreCreate(ctx, "sb-store", models.ErrSandboxExists)
	if err != nil || resp.Sandbox.ID != "sb-store" {
		t.Fatalf("resp = %+v err = %v", resp, err)
	}
}

func TestReturnExistingSandboxResponse(t *testing.T) {
	svc, _ := dockerPoolServiceHarness(t)
	if resp, ok := svc.returnExistingSandboxResponse(context.Background(), "nope"); ok || resp != nil {
		t.Fatal("expected miss")
	}
}
