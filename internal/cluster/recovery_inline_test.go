package cluster

import (
	"context"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// oversizedSpec returns a spec whose encoded recovery record exceeds
// inlineRecoveryMaxBytes, forcing the blob path without sealed bytes.
func oversizedSpec(name string) *models.CreateSandboxRequest {
	return &models.CreateSandboxRequest{
		Name:  name,
		Image: "alpine:" + strings.Repeat("x", inlineRecoveryMaxBytes),
	}
}

// TestExternalizeInlineEligibleSkipsBlobPath pins the Tier 2 contract: a
// small, secret-free payload stays inline in the raft command — no blob is
// stored or replicated before the apply, and the command keeps its original
// wire shape (the one hydrateCommandRecovery no-ops on).
func TestExternalizeInlineEligibleSkipsBlobPath(t *testing.T) {
	cases := []struct {
		name string
		cmd  command
	}{
		{
			name: "small spec with secret handle",
			cmd: command{
				Op:            opPlace,
				SandboxID:     "sb-inline",
				OwnerNodeID:   "node-a",
				Spec:          &models.CreateSandboxRequest{Name: "inline", Image: "alpine:3.20"},
				SecretRef:     "provider-ref-1",
				SecretVersion: 3,
			},
		},
		{
			name: "secret handle only",
			cmd: command{
				Op:            opUpsertSpec,
				SandboxID:     "sb-handle-only",
				SecretRef:     "provider-ref-2",
				SecretVersion: 1,
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			put := func(ctx context.Context, blob RecoveryBlob) error {
				t.Fatalf("blob put called for inline-eligible payload: %+v", blob)
				return nil
			}
			out, err := externalizeCommandRecovery(context.Background(), tc.cmd, put)
			if err != nil {
				t.Fatalf("externalize: %v", err)
			}
			if out.RecoveryRef != "" {
				t.Fatalf("inline command gained RecoveryRef %q", out.RecoveryRef)
			}
			if (out.Spec == nil) != (tc.cmd.Spec == nil) || out.SecretRef != tc.cmd.SecretRef || out.SecretVersion != tc.cmd.SecretVersion {
				t.Fatalf("inline command payload mutated: %+v", out)
			}
		})
	}
}

// TestExternalizeBlobPathForSealedAndOversized pins the two conditions that
// must keep using the blob mesh: legacy sealed secret bytes (never allowed in
// the immutable raft log) and payloads over inlineRecoveryMaxBytes.
func TestExternalizeBlobPathForSealedAndOversized(t *testing.T) {
	cases := []struct {
		name string
		cmd  command
	}{
		{
			name: "legacy sealed secrets",
			cmd: command{
				Op:            opPlace,
				SandboxID:     "sb-sealed",
				OwnerNodeID:   "node-a",
				Spec:          &models.CreateSandboxRequest{Name: "sealed", Image: "alpine:3.20"},
				SealedSecrets: []byte("sealed-bytes"),
			},
		},
		{
			name: "oversized spec",
			cmd: command{
				Op:          opPlace,
				SandboxID:   "sb-big",
				OwnerNodeID: "node-a",
				Spec:        oversizedSpec("big"),
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			puts := 0
			put := func(ctx context.Context, blob RecoveryBlob) error {
				puts++
				return nil
			}
			out, err := externalizeCommandRecovery(context.Background(), tc.cmd, put)
			if err != nil {
				t.Fatalf("externalize: %v", err)
			}
			if puts != 1 {
				t.Fatalf("blob put called %d times, want 1", puts)
			}
			if out.RecoveryRef == "" {
				t.Fatal("blob-path command missing RecoveryRef")
			}
			if out.Spec != nil || out.SecretRef != "" || out.SecretVersion != 0 || len(out.SealedSecrets) != 0 {
				t.Fatalf("blob-path command still carries payload: %+v", out)
			}
			if out.Name != commandName(tc.cmd) {
				t.Fatalf("blob-path command Name = %q, want %q", out.Name, commandName(tc.cmd))
			}
		})
	}
}

// TestExternalizeReserveBatchMixedEligibility pins per-reservation gating:
// one opReserveBatch may carry inline and ref reservations side by side.
func TestExternalizeReserveBatchMixedEligibility(t *testing.T) {
	puts := 0
	put := func(ctx context.Context, blob RecoveryBlob) error {
		puts++
		return nil
	}
	cmd := command{
		Op: opReserveBatch,
		Reservations: []reservationCommand{
			{SandboxID: "sb-small", OwnerNodeID: "node-a", Spec: &models.CreateSandboxRequest{Name: "small", Image: "alpine:3.20"}},
			{SandboxID: "sb-sealed", OwnerNodeID: "node-a", Spec: &models.CreateSandboxRequest{Name: "sealed"}, SealedSecrets: []byte("sealed")},
			{SandboxID: "sb-big", OwnerNodeID: "node-a", Spec: oversizedSpec("big")},
		},
	}
	out, err := externalizeCommandRecovery(context.Background(), cmd, put)
	if err != nil {
		t.Fatalf("externalize: %v", err)
	}
	if puts != 2 {
		t.Fatalf("blob put called %d times, want 2", puts)
	}
	if r := out.Reservations[0]; r.RecoveryRef != "" || r.Spec == nil {
		t.Fatalf("small reservation should stay inline: %+v", r)
	}
	for _, i := range []int{1, 2} {
		if r := out.Reservations[i]; r.RecoveryRef == "" || r.Spec != nil || len(r.SealedSecrets) != 0 {
			t.Fatalf("reservation %d should be blob-externalized: %+v", i, r)
		}
	}
}

// TestInlineRecoveryEligible pins the gate directly, including that sealed
// bytes disqualify regardless of size.
func TestInlineRecoveryEligible(t *testing.T) {
	small := placementRecovery{Spec: &models.CreateSandboxRequest{Name: "n", Image: "alpine"}, SecretRef: "r", SecretVersion: 1}
	if ok, err := inlineRecoveryEligible("sb", small); err != nil || !ok {
		t.Fatalf("small secret-free payload: eligible=%v err=%v, want true", ok, err)
	}
	sealedTiny := placementRecovery{SealedSecrets: []byte{1}}
	if ok, err := inlineRecoveryEligible("sb", sealedTiny); err != nil || ok {
		t.Fatalf("sealed payload: eligible=%v err=%v, want false", ok, err)
	}
	big := placementRecovery{Spec: oversizedSpec("n")}
	if ok, err := inlineRecoveryEligible("sb", big); err != nil || ok {
		t.Fatalf("oversized payload: eligible=%v err=%v, want false", ok, err)
	}
}
