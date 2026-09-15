package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/controlplane"
	"github.com/aerol-ai/microvm/pkg/models"
)

// stubAdmitter denies creates for owners present in deny, with the mapped error.
type stubAdmitter struct{ deny map[string]error }

func (s stubAdmitter) Admit(_ context.Context, owner string) error { return s.deny[owner] }

// createOwned creates a sandbox attributed to owner via an access-scoped ctx and
// returns its id. The harness runtime brings it up Started.
func createOwned(t *testing.T, svc *Service, owner, id string) string {
	t.Helper()
	resp, err := svc.CreateSandboxWithID(userCtx(owner), models.CreateSandboxRequest{Image: "ubuntu:22.04"}, id)
	if err != nil {
		t.Fatalf("CreateSandboxWithID(%s/%s): %v", owner, id, err)
	}
	return resp.ID
}

func statusOf(t *testing.T, svc *Service, id string) (models.SandboxStatus, bool) {
	t.Helper()
	// Operator ctx so the read is never owner-scoped.
	sb, err := svc.store.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("store.Get(%s): %v", id, err)
	}
	return sb.Status, sb.FleetSuspended
}

func TestFleetControllerStopRestoreByOwner(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	bg := context.Background()

	a1 := createOwned(t, svc, "acme", "sb-a1")
	a2 := createOwned(t, svc, "acme", "sb-a2")
	other := createOwned(t, svc, "other", "sb-o1")

	// Suspend acme: both acme sandboxes stop and are marked fleet-suspended; the
	// other owner is untouched.
	if err := svc.StopByOwner(bg, "acme"); err != nil {
		t.Fatalf("StopByOwner: %v", err)
	}
	for _, id := range []string{a1, a2} {
		if st, susp := statusOf(t, svc, id); st != models.SandboxStatusStopped || !susp {
			t.Fatalf("after suspend %s: status=%q suspended=%v, want stopped/true", id, st, susp)
		}
	}
	if st, susp := statusOf(t, svc, other); st != models.SandboxStatusStarted || susp {
		t.Fatalf("other owner %s: status=%q suspended=%v, want started/false (untouched)", other, st, susp)
	}
	stopsAfterFirst := len(rt.stopRefs)

	// Idempotent: a second suspend over the now-stopped set issues no new stops.
	if err := svc.StopByOwner(bg, "acme"); err != nil {
		t.Fatalf("StopByOwner (2nd): %v", err)
	}
	if len(rt.stopRefs) != stopsAfterFirst {
		t.Fatalf("second suspend issued extra stops: %d -> %d", stopsAfterFirst, len(rt.stopRefs))
	}

	// Restore acme: marked sandboxes restart and the marker clears.
	rt.startState = &models.SandboxRuntimeState{ContainerID: "ctr-restart", ContainerIP: "10.0.0.5", Status: models.SandboxStatusStarted}
	if err := svc.RestoreByOwner(bg, "acme"); err != nil {
		t.Fatalf("RestoreByOwner: %v", err)
	}
	for _, id := range []string{a1, a2} {
		if st, susp := statusOf(t, svc, id); st != models.SandboxStatusStarted || susp {
			t.Fatalf("after restore %s: status=%q suspended=%v, want started/false", id, st, susp)
		}
	}

	// Idempotent: restoring again does nothing (no marker left to act on).
	if err := svc.RestoreByOwner(bg, "acme"); err != nil {
		t.Fatalf("RestoreByOwner (2nd): %v", err)
	}
}

func TestFleetControllerDeleteByOwner(t *testing.T) {
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	bg := context.Background()

	a1 := createOwned(t, svc, "acme", "sb-d1")
	a2 := createOwned(t, svc, "acme", "sb-d2")
	other := createOwned(t, svc, "other", "sb-d3")

	if err := svc.DeleteByOwner(bg, "acme"); err != nil {
		t.Fatalf("DeleteByOwner: %v", err)
	}
	for _, id := range []string{a1, a2} {
		if _, err := st.Get(bg, id); err == nil {
			t.Fatalf("sandbox %s still present after DeleteByOwner", id)
		}
	}
	// Other owner survives.
	if _, err := st.Get(bg, other); err != nil {
		t.Fatalf("other owner %s should survive delete-by-owner: %v", other, err)
	}

	// Idempotent: re-deleting an already-empty owner is a no-op success.
	if err := svc.DeleteByOwner(bg, "acme"); err != nil {
		t.Fatalf("DeleteByOwner (2nd): %v", err)
	}
}

func TestFleetControllerRestoreRespectsUserStop(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	bg := context.Background()

	id := createOwned(t, svc, "acme", "sb-u1")
	// A user stops their own sandbox (not a fleet suspension).
	if _, err := svc.StopSandbox(userCtx("acme"), id); err != nil {
		t.Fatalf("StopSandbox: %v", err)
	}
	// RestoreByOwner must NOT restart it: it was never fleet-suspended.
	if err := svc.RestoreByOwner(bg, "acme"); err != nil {
		t.Fatalf("RestoreByOwner: %v", err)
	}
	if st, susp := statusOf(t, svc, id); st != models.SandboxStatusStopped || susp {
		t.Fatalf("user-stopped %s after restore: status=%q suspended=%v, want stopped/false (left alone)", id, st, susp)
	}
}

func TestFleetControllerFireWebhookIsNoErr(t *testing.T) {
	rt := &recordingRuntime{}
	svc, _, _ := newServiceRuntimeHarness(t, rt)
	if err := svc.FireWebhook(context.Background(), "acme", "warn"); err != nil {
		t.Fatalf("FireWebhook: %v", err)
	}
}

func TestFleetControllerErrorBranches(t *testing.T) {
	bg := context.Background()

	t.Run("stop errors are joined", func(t *testing.T) {
		rt := &recordingRuntime{stopErr: errors.New("stop failed")}
		svc, st, _ := newServiceRuntimeHarness(t, rt)
		id := createOwned(t, svc, "acme", "sb-stop-err")
		if err := svc.StopByOwner(bg, "acme"); err == nil {
			t.Fatal("expected StopByOwner to return error")
		}
		got, err := st.Get(bg, id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.Status != models.SandboxStatusStarted {
			t.Fatalf("stop failure should leave sandbox running, got %s", got.Status)
		}
	})

	t.Run("restore errors are joined", func(t *testing.T) {
		rt := &recordingRuntime{startErr: errors.New("start failed")}
		svc, st, _ := newServiceRuntimeHarness(t, rt)
		id := createOwned(t, svc, "acme", "sb-restore-err")
		if _, err := svc.StopSandbox(bg, id); err != nil {
			t.Fatalf("StopSandbox: %v", err)
		}
		rt.startErr = errors.New("start failed")
		if err := st.SetFleetSuspended(bg, id, true); err != nil {
			t.Fatalf("SetFleetSuspended: %v", err)
		}
		if err := st.UpdateStatus(bg, id, models.SandboxStatusStopped, ""); err != nil {
			t.Fatalf("UpdateStatus: %v", err)
		}
		if err := svc.RestoreByOwner(bg, "acme"); err == nil {
			t.Fatal("expected RestoreByOwner to return error")
		}
		got, err := st.Get(bg, id)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !got.FleetSuspended {
			t.Fatal("failed restore should preserve fleet-suspended marker")
		}
	})

	t.Run("delete errors are surfaced", func(t *testing.T) {
		rt := &recordingRuntime{destroyErr: errors.New("destroy failed")}
		svc, _, _ := newServiceRuntimeHarness(t, rt)
		createOwned(t, svc, "acme", "sb-delete-err")
		if err := svc.DeleteByOwner(bg, "acme"); err == nil {
			t.Fatal("expected DeleteByOwner to return error")
		}
	})

	t.Run("list errors are returned", func(t *testing.T) {
		rt := &recordingRuntime{}
		svc, _, _ := newServiceRuntimeHarness(t, rt)
		st2, err := store.Open(filepath.Join(t.TempDir(), "owner.db"))
		if err != nil {
			t.Fatalf("store.Open: %v", err)
		}
		st2.SetSecretCipher(svc.cipher)
		svc.store = st2
		createOwned(t, svc, "acme", "sb-owner-list")
		if err := st2.Close(); err != nil {
			t.Fatalf("store.Close: %v", err)
		}
		if err := svc.StopByOwner(bg, "acme"); err == nil {
			t.Fatal("expected StopByOwner list failure")
		}
		if err := svc.RestoreByOwner(bg, "acme"); err == nil {
			t.Fatal("expected RestoreByOwner list failure")
		}
		if err := svc.DeleteByOwner(bg, "acme"); err == nil {
			t.Fatal("expected DeleteByOwner list failure")
		}
	})
}

func TestCreateGate(t *testing.T) {
	rt := &recordingRuntime{}
	svc, st, _ := newServiceRuntimeHarness(t, rt)
	svc.SetFleetAdmitter(stubAdmitter{deny: map[string]error{
		"blocked": controlplane.ErrAdmissionDenied,
	}})

	// Denied owner: create is refused before any sandbox row is written.
	_, err := svc.CreateSandboxWithID(userCtx("blocked"), models.CreateSandboxRequest{Image: "ubuntu:22.04"}, "sb-blocked")
	if !errors.Is(err, controlplane.ErrAdmissionDenied) {
		t.Fatalf("blocked create: got %v, want ErrAdmissionDenied", err)
	}
	if _, gerr := st.Get(context.Background(), "sb-blocked"); !errors.Is(gerr, store.ErrNotFound) {
		t.Fatalf("denied create must not persist a row, got %v", gerr)
	}

	// Permitted owner: gate admits, create succeeds.
	if _, err := svc.CreateSandboxWithID(userCtx("ok"), models.CreateSandboxRequest{Image: "ubuntu:22.04"}, "sb-ok"); err != nil {
		t.Fatalf("permitted create: %v", err)
	}

	// Operator / owner-less create bypasses the gate entirely (ownerRef == "").
	if _, err := svc.CreateSandboxWithID(operatorCtx(), models.CreateSandboxRequest{Image: "ubuntu:22.04"}, "sb-op"); err != nil {
		t.Fatalf("operator create should bypass gate: %v", err)
	}
}
