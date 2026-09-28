package service

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestReturningReplicaRetiresSupersededGenerationWithoutOriginator(t *testing.T) {
	for _, tc := range []struct {
		name       string
		generation int64
		recipients []string
		ref        string
		retire     bool
	}{
		{"removed recipient", 2, []string{"owner", "replacement"}, "", true},
		{"removed at promoted generation", 1, []string{"owner", "replacement"}, "", true},
		{"lagging current recipient", 2, []string{"owner", "returning"}, "", true},
		{"current backup", 1, []string{"owner", "returning"}, "", false},
		{"staged generation ahead of raft", 1, []string{"owner", "replacement"}, "", false},
		{"unknown generation", 0, []string{"owner", "replacement"}, "", false},
		{"unrelated ref", 2, []string{"owner", "replacement"}, "invalid-ref", false},
		{"unknown recipients", 2, nil, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := secrets.ContextWithIncarnationID(context.Background(), "inc-live")
			st := openSealTestStore(t)
			cipher := newTestCipher(t)
			provider := secrets.NewLocalProvider(cipher, newSecretBlobStore(st))
			handle, err := provider.Put(ctx, "sb-returning", secrets.Secrets{Env: map[string]string{"K": "V"}}, []string{"owner", "returning"})
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "staged generation ahead of raft" {
				handle, err = provider.Put(ctx, "sb-returning", secrets.Secrets{Env: map[string]string{"K": "V"}}, []string{"owner", "returning"})
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := st.UpsertSecretPutOutbox(ctx, "sb-returning", "inc-live", handle.SealGeneration, []string{"owner"}); err != nil {
				t.Fatal(err)
			}
			ref := tc.ref
			if ref == "" {
				ref = handle.Ref
			}
			cl := &placementOnlyCluster{Noop: cluster.NewNoop("returning", "http://returning", ""), placement: cluster.Placement{
				SandboxID: "sb-returning", OwnerNodeID: "owner", IncarnationID: "inc-live", SecretRef: ref,
				SecretSealGeneration: tc.generation, SecretRecipients: tc.recipients,
			}}
			svc := &Service{cfg: config.Config{EnableCluster: true}, store: st, cluster: cl}
			for range 2 {
				if err := svc.runSecretRetirementScan(ctx); err != nil {
					t.Fatal(err)
				}
			}
			rec, err := st.GetClusterSecretForSandboxIncarnation(ctx, "sb-returning", "inc-live")
			if (err != nil && !errors.Is(err, store.ErrNotFound)) || (rec == nil) != tc.retire {
				t.Fatalf("retired=%v want=%v err=%v", rec == nil, tc.retire, err)
			}
			outbox, err := st.GetSecretDeleteOutboxForIncarnation(ctx, "sb-returning", "inc-live")
			if err != nil || outbox != nil {
				t.Fatalf("replica created destructive fanout: %+v %v", outbox, err)
			}
			if tc.retire {
				put, err := st.GetSecretPutOutboxForIncarnation(ctx, "sb-returning", "inc-live")
				if err != nil || put != nil {
					t.Fatalf("stale PUT outbox remains: %+v %v", put, err)
				}
				if _, err := provider.Open(ctx, "sb-returning", handle, "returning"); err == nil {
					t.Fatal("retired ciphertext still opens")
				}
			}
		})
	}
}
