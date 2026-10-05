package service

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestCoverage97PendingIncarnationAndFailoverBatch(t *testing.T) {
	svc := &Service{pendingAuditIncarnation: map[string]string{"sb-pending": "already"}}
	got, err := svc.prepareAuditIncarnation(context.Background(), "sb-pending", "")
	if err != nil || got != "already" {
		t.Fatalf("pending incarnation = %q, %v", got, err)
	}

	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	st.Close()
	ready := &Service{
		store:  st,
		logger: slog.New(slog.DiscardHandler),
		cluster: &placementOnlyCluster{
			Noop: cluster.NewNoop("node-a", "http://node-a", ""),
			placement: cluster.Placement{
				SandboxID:     "sb-ready",
				IncarnationID: "inc-ready",
			},
		},
	}
	sb := &models.Sandbox{
		ID:       "sb-ready",
		Failover: &models.Failover{Policy: models.FailoverPolicyRecreate},
	}
	ready.failoverReadyBatch(context.Background(), []*models.Sandbox{nil, sb})
	if sb.FailoverReady == nil || *sb.FailoverReady {
		t.Fatalf("failover ready = %v, want false", sb.FailoverReady)
	}
}
