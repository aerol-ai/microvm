package clustercreate

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/cluster"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestCreateOnSelectedNodeRefusesAPastDestroyAt (plan L6): the facades'
// shared create converts destroy_at before the spec is promoted, and a past
// time is refused before any work.
func TestCreateOnSelectedNodeRefusesAPastDestroyAt(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stub := &clusterStub{Noop: cluster.NewNoop("node-a", "http://node-a", "")}
	svc, _ := newCreateService(t, stub, false)
	past := time.Now().UTC().Add(-time.Minute)
	_, err := CreateOnSelectedNode(context.Background(), svc, logger, models.CreateSandboxRequest{
		Image: "alpine:3.20", Lifecycle: &models.Lifecycle{DestroyAt: &past},
	}, "", CreateOptions{})
	if err == nil || !strings.Contains(err.Error(), "destroy_at") {
		t.Fatalf("past destroy_at = %v", err)
	}
}
