package cluster

import (
	"bytes"
	"context"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/hashicorp/raft"
)

func TestExternalizedRecoveryDoesNotEnterRaftCommand(t *testing.T) {
	store := newPlacementRecoveryMemoryStore()
	put := func(ctx context.Context, blob RecoveryBlob) error {
		_ = ctx
		ref, err := store.Put(blob.SandboxID, blob.recovery())
		if err != nil {
			return err
		}
		if ref != blob.Ref {
			t.Fatalf("stored ref=%q want %q", ref, blob.Ref)
		}
		return nil
	}
	cmd := command{
		Op:            opReserve,
		SandboxID:     "sb-externalized",
		OwnerNodeID:   "node-a",
		Spec:          &models.CreateSandboxRequest{Name: "named", Image: "image-only-in-recovery"},
		SealedSecrets: []byte("sealed-only-in-recovery"),
		ExpiresUnix:   9999999999,
	}
	raftCmd, err := externalizeCommandRecovery(context.Background(), cmd, put)
	if err != nil {
		t.Fatalf("externalize: %v", err)
	}
	if raftCmd.Spec != nil || len(raftCmd.SealedSecrets) != 0 || raftCmd.SecretRef != "" || raftCmd.SecretVersion != 0 {
		t.Fatalf("raft command still carries recovery payload: %+v", raftCmd)
	}
	if raftCmd.Name != "named" || raftCmd.RecoveryRef == "" {
		t.Fatalf("raft command missing hot recovery fields: %+v", raftCmd)
	}
	payload, err := encodeCommand(raftCmd)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for _, forbidden := range [][]byte{[]byte("image-only-in-recovery"), []byte("sealed-only-in-recovery")} {
		if bytes.Contains(payload, forbidden) {
			t.Fatalf("raft payload contained recovery bytes %q", forbidden)
		}
	}

	fsm := newPlacementFSMWithRecoveryStore(store)
	if got := fsm.Apply(&raft.Log{Index: 1, Data: payload}); got != nil {
		t.Fatalf("apply externalized command: %v", got)
	}
	placement, ok := fsm.get("sb-externalized")
	if !ok {
		t.Fatal("placement missing after externalized apply")
	}
	if placement.Spec == nil || placement.Spec.Image != "image-only-in-recovery" {
		t.Fatalf("externalized spec was not hydrated: %+v", placement.Spec)
	}
	if string(placement.SealedSecrets) != "sealed-only-in-recovery" {
		t.Fatalf("externalized sealed secrets were not hydrated: %q", placement.SealedSecrets)
	}
}
