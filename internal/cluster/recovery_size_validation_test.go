package cluster

import (
	"errors"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// oversizedSpec returns a spec whose encoded recovery record exceeds
// inlineRecoveryMaxBytes. With no blob fallback, this must be rejected.
func oversizedSpec(name string) *models.CreateSandboxRequest {
	return &models.CreateSandboxRequest{
		Name:  name,
		Image: "alpine:" + strings.Repeat("x", inlineRecoveryMaxBytes),
	}
}

// specEncodingTo builds a spec whose encoded recovery record for (sandboxID,
// secrets) is exactly target bytes, by measuring the fixed overhead once and
// padding the image tag with 'x' (one byte of tag = one byte of JSON).
func specEncodingTo(t *testing.T, target int, sandboxID string, secrets PlacementSecrets) *models.CreateSandboxRequest {
	t.Helper()
	base := &models.CreateSandboxRequest{Name: "boundary", Image: "alpine:"}
	rec := placementRecovery{Spec: base, SecretRef: secrets.Ref, SecretVersion: secrets.Version}
	_, payload, err := encodePlacementRecoveryRecord(placementRecoveryStoreRecord{SandboxID: sandboxID, Recovery: rec})
	if err != nil {
		t.Fatalf("encode baseline: %v", err)
	}
	pad := target - len(payload)
	if pad < 0 {
		t.Fatalf("baseline record already %d bytes, over target %d", len(payload), target)
	}
	out := *base
	out.Image = base.Image + strings.Repeat("x", pad)
	return &out
}

// TestValidateRecoveryPayloadSizeBoundary pins the validation cap at its
// exact edge: a record of exactly inlineRecoveryMaxBytes is accepted, one
// byte more is rejected with ErrRecoveryPayloadTooLarge. This is the
// user-facing 400 contract from plans/remove-legacy-recovery-blob-path.md §3.
func TestValidateRecoveryPayloadSizeBoundary(t *testing.T) {
	secrets := PlacementSecrets{Ref: "cluster-secret://sandbox/sb-boundary/v1", Version: 1}

	atLimit := specEncodingTo(t, inlineRecoveryMaxBytes, "sb-boundary", secrets)
	if err := ValidateRecoveryPayloadSize("sb-boundary", atLimit, secrets); err != nil {
		t.Fatalf("record at exactly %d bytes rejected: %v", inlineRecoveryMaxBytes, err)
	}

	overLimit := specEncodingTo(t, inlineRecoveryMaxBytes+1, "sb-boundary", secrets)
	err := ValidateRecoveryPayloadSize("sb-boundary", overLimit, secrets)
	if !errors.Is(err, ErrRecoveryPayloadTooLarge) {
		t.Fatalf("record one byte over limit: err=%v, want ErrRecoveryPayloadTooLarge", err)
	}
	// The error must name the sandbox and both sizes — an opaque 400 here is
	// the support trap plan §6 warns about.
	for _, needle := range []string{"sb-boundary", "4097", "4096"} {
		if !strings.Contains(err.Error(), needle) {
			t.Fatalf("oversize error %q missing %q", err.Error(), needle)
		}
	}
}

// TestValidateCommandRecoverySize pins the defensive half: every
// payload-carrying op is checked before raft encode, ops without a payload
// are not, and one oversized reservation fails the whole batch.
func TestValidateCommandRecoverySize(t *testing.T) {
	small := &models.CreateSandboxRequest{Name: "small", Image: "alpine:3.20"}

	if err := validateCommandRecoverySize(command{Op: opPlace, SandboxID: "sb-ok", Spec: small, SecretRef: "r", SecretVersion: 1}); err != nil {
		t.Fatalf("small opPlace payload rejected: %v", err)
	}
	if err := validateCommandRecoverySize(command{Op: opCancelReserve, SandboxID: "sb-nopayload"}); err != nil {
		t.Fatalf("payload-free op validated/rejected: %v", err)
	}
	for _, op := range []opCode{opPlace, opClaimOrphan, opUpsertSpec, opReserve} {
		err := validateCommandRecoverySize(command{Op: op, SandboxID: "sb-big", Spec: oversizedSpec("big")})
		if !errors.Is(err, ErrRecoveryPayloadTooLarge) {
			t.Fatalf("op %d oversized payload: err=%v, want ErrRecoveryPayloadTooLarge", op, err)
		}
	}

	batch := command{
		Op: opReserveBatch,
		Reservations: []reservationCommand{
			{SandboxID: "sb-small", OwnerNodeID: "node-a", Spec: small},
			{SandboxID: "sb-big", OwnerNodeID: "node-a", Spec: oversizedSpec("big")},
		},
	}
	if err := validateCommandRecoverySize(batch); !errors.Is(err, ErrRecoveryPayloadTooLarge) {
		t.Fatalf("batch with oversized reservation: err=%v, want ErrRecoveryPayloadTooLarge", err)
	}
	okBatch := command{
		Op: opReserveBatch,
		Reservations: []reservationCommand{
			{SandboxID: "sb-a", OwnerNodeID: "node-a", Spec: small},
			{SandboxID: "sb-b", OwnerNodeID: "node-a"},
		},
	}
	if err := validateCommandRecoverySize(okBatch); err != nil {
		t.Fatalf("small batch rejected: %v", err)
	}
}
