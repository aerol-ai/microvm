package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A keyed create that meets a failed earlier create's leftover instance
// (UC-450: the client hung up while the engine was creating the container)
// removes it under the ID's create lease and creates again, so the retry
// gets its sandbox, not 409. Without the lease, or when the removal fails,
// the answer stays ErrSandboxExists.
func TestCreateRemovesAFailedCreatesLeftoverInstance(t *testing.T) {
	const id = "sb-leftover00001"
	for _, tc := range []struct {
		name        string
		destroyErr  error
		viaLease    bool
		wantErr     error
		wantCreates int
		wantDestroy bool
	}{
		{name: "keyed create removes it and creates", viaLease: true, wantCreates: 2, wantDestroy: true},
		{name: "a removal that fails keeps the 409", viaLease: true, destroyErr: errors.New("engine down"), wantErr: models.ErrSandboxExists, wantCreates: 1, wantDestroy: true},
		// createSandbox alone reports the leftover but never removes it: only
		// CreateSandboxWithID, the keyed entry point, removes and retries.
		// The lease and no-row guards are tested directly in
		// TestAsLeftoverInstanceNeedsTheLeaseAndNoRow.
		{name: "createSandbox alone removes nothing", viaLease: false, wantErr: models.ErrSandboxExists, wantCreates: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rt := &recordingRuntime{leftover: map[string]bool{id: true}, destroyErr: tc.destroyErr}
			svc, st, _ := newServiceRuntimeHarness(t, rt)
			svc.admitter = nil
			req := models.CreateSandboxRequest{Image: "alpine:3.20"}
			var (
				resp *models.CreateSandboxResponse
				err  error
			)
			if tc.viaLease {
				resp, err = svc.CreateSandboxWithID(t.Context(), req, id)
			} else {
				resp, err = svc.createSandbox(t.Context(), req, id)
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) || resp != nil {
					t.Fatalf("create = %+v, %v; want %v", resp, err, tc.wantErr)
				}
			} else if err != nil || resp == nil || resp.Sandbox.ID != id {
				t.Fatalf("create = %+v, %v; want sandbox %s", resp, err, id)
			}
			if rt.createCalls != tc.wantCreates {
				t.Fatalf("runtime creates = %d, want %d", rt.createCalls, tc.wantCreates)
			}
			if got := slices.Contains(rt.destroyIDs, id); got != tc.wantDestroy {
				t.Fatalf("leftover destroyed = %v (destroys %v), want %v", got, rt.destroyIDs, tc.wantDestroy)
			}
			if tc.wantErr == nil {
				if row, err := st.Get(t.Context(), id); err != nil || row == nil {
					t.Fatalf("row after the retry = %v, %v; want it stored", row, err)
				}
			}
		})
	}
}

// A sandbox that really exists (a row) is never treated as a leftover: the
// collision replays it, and nothing is destroyed.
func TestCreateNeverRemovesALiveSandbox(t *testing.T) {
	const id = "sb-leftover00002"
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	svc.admitter = nil
	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	if _, err := svc.CreateSandboxWithID(t.Context(), req, id); err != nil {
		t.Fatal(err)
	}
	rt.leftover = map[string]bool{id: true}
	resp, err := svc.CreateSandboxWithID(t.Context(), req, id)
	if err != nil || resp == nil || !resp.Replayed {
		t.Fatalf("second create = %+v, %v; want a replay", resp, err)
	}
	if len(rt.destroyIDs) != 0 {
		t.Fatalf("destroys = %v, want none", rt.destroyIDs)
	}
}

// asLeftoverInstance turns a collision into a leftover only when all three
// hold: the error is ErrSandboxExists, this create holds the ID's lease, and
// no row has the ID. Each other combination returns the error unchanged.
func TestAsLeftoverInstanceNeedsTheLeaseAndNoRow(t *testing.T) {
	const id = "sb-leftover00003"
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	leased := context.WithValue(t.Context(), createLeaseCtxKey{}, id)
	exists := fmt.Errorf("%w: sandbox container already exists", models.ErrSandboxExists)

	var leftover *leftoverInstanceError
	if got := svc.asLeftoverInstance(leased, exists, rt, id, "docker", "docker"); !errors.As(got, &leftover) || !errors.Is(got, models.ErrSandboxExists) {
		t.Fatalf("lease and no row = %v, want a leftover that still reads as ErrSandboxExists", got)
	}
	if got := svc.asLeftoverInstance(t.Context(), exists, rt, id, "docker", "docker"); errors.As(got, &leftover) {
		t.Fatalf("no lease = %v, want the error unchanged", got)
	}
	other := errors.New("engine down")
	if got := svc.asLeftoverInstance(leased, other, rt, id, "docker", "docker"); got != other {
		t.Fatalf("other error = %v, want it unchanged", got)
	}
	if got := svc.asLeftoverInstance(leased, exists, nil, id, "docker", "docker"); errors.As(got, &leftover) {
		t.Fatalf("no runtime = %v, want the error unchanged", got)
	}
	now := time.Now().UTC()
	if err := st.Create(t.Context(), &models.Sandbox{ID: id, Name: id, Image: "alpine:3.20", Status: models.SandboxStatusStarted, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatal(err)
	}
	if got := svc.asLeftoverInstance(leased, exists, rt, id, "docker", "docker"); errors.As(got, &leftover) {
		t.Fatalf("row exists = %v, want the error unchanged (a live sandbox is never a leftover)", got)
	}
}

// removeLeftoverInstance reads the instance first, so the runtime destroys
// it by its real container ID and clears what is keyed by its address.
func TestRemoveLeftoverInstanceUsesWhatInspectFinds(t *testing.T) {
	const id = "sb-leftover00004"
	rt := &recordingRuntime{inspect: map[string]*models.SandboxRuntimeState{
		id: {SandboxID: id, ContainerID: "ctr-abc", ContainerIP: "10.88.0.9"},
	}}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	if err := svc.removeLeftoverInstance(t.Context(), id, &leftoverInstanceError{rt: rt, runtime: "docker", engine: "docker"}); err != nil {
		t.Fatal(err)
	}
	if len(rt.destroyIDs) != 1 || rt.destroyIDs[0] != id {
		t.Fatalf("destroys = %v, want %s", rt.destroyIDs, id)
	}
	if rt.lastDestroyed == nil || rt.lastDestroyed.ContainerID != "ctr-abc" || rt.lastDestroyed.ContainerIP != "10.88.0.9" {
		t.Fatalf("destroyed %+v, want the inspected container ID and address", rt.lastDestroyed)
	}
}
