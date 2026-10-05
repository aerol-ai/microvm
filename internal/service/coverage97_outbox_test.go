package service

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

func TestCoverage97PutOutboxIdentityAndPersist(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })

	put := func(id, inc string, gen int64) {
		t.Helper()
		if _, err := st.PutClusterSecret(context.Background(), store.ClusterSecretRecord{
			Ref:            secrets.FormatRef(id, inc, secrets.RefVersion),
			SandboxID:      id,
			Version:        secrets.RefVersion,
			Recipients:     []string{"peer"},
			SealedPayload:  []byte("sealed-bytes-not-plaintext"),
			SealGeneration: gen,
		}); err != nil {
			t.Fatalf("PutClusterSecret(%s): %v", id, err)
		}
	}
	svcFor := func(pushErr error, ack []string) *Service {
		return &Service{
			store:  st,
			logger: slog.New(slog.DiscardHandler),
			cluster: &cov97SecretPusher{
				Noop:    cluster.NewNoop("node-a", "http://node-a", ""),
				pushErr: pushErr,
				pushAck: ack,
			},
		}
	}

	put("sb-bad-gen", "inc-bad", 2)
	svcFor(nil, nil).reconcileSecretPutOutboxRecord(context.Background(), &store.SecretPutOutboxRecord{
		SandboxID: "sb-bad-gen", IncarnationID: "inc-bad", SealGeneration: 0, Recipients: []string{"peer"},
	}, nil)

	put("sb-push-err", "inc-push", 2)
	svcFor(errors.New("peer down"), nil).reconcileSecretPutOutboxRecord(context.Background(), &store.SecretPutOutboxRecord{
		SandboxID: "sb-push-err", IncarnationID: "inc-push", SealGeneration: 2, Recipients: []string{"peer"},
	}, nil)

	put("sb-persist", "inc-persist", 2)
	svcFor(nil, []string{"peer"}).reconcileSecretPutOutboxRecord(context.Background(), &store.SecretPutOutboxRecord{
		SandboxID: "sb-persist", IncarnationID: "inc-persist", SealGeneration: 2, Recipients: []string{"peer"},
	}, nil)
}
