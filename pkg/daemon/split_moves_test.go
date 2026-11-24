package daemon

import (
	"context"
	"io"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/rootd/rootdpb"
	"github.com/aerol-ai/microvm/internal/service"
)

// moveEngineHelper is the engine's helper with gVisor move calls (M1 PR
// 13), recording the drops it is asked for.
type moveEngineHelper struct {
	*engineHelper
	mu      sync.Mutex
	dropped []string
}

func (*moveEngineHelper) CheckpointMove(context.Context, string) error        { return nil }
func (*moveEngineHelper) ExportMove(context.Context, string, io.Writer) error { return nil }
func (*moveEngineHelper) ImportMove(context.Context, string, io.Reader) (string, error) {
	return "", nil
}
func (*moveEngineHelper) StagedMove(context.Context, string) (string, error) { return "", nil }
func (h *moveEngineHelper) DropMove(_ context.Context, id string, sides ...rootdpb.MoveSide) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, s := range sides {
		h.dropped = append(h.dropped, id+" "+s.String())
	}
	return nil
}

// TestWireContainerEngineSplitMoves: with gVisor checkpoint moves on, a
// split node's driver takes a move's checkpoints through the helper, and
// a helper client with no move calls stops the node at start.
func TestWireContainerEngineSplitMoves(t *testing.T) {
	st := openDaemonTestStore(t)
	cfg := splitConfig()
	cfg.ContainerdNamespace, cfg.ContainerdSocket = "aerolvm", "/run/containerd/containerd.sock"
	cfg.ContainerdNetnsPoolSize, cfg.ContainerdNetnsPoolRefillInterval = 1, time.Hour
	cfg.ContainerdBridgeSubnet = "10.88.0.0/16"
	cfg.GvisorCheckpointMoves = true
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	svc := service.New(config.Config{}, testLogger(), st, nil, nil, nil, nil, nil, nil)
	if _, err := wireContainerEngineWith(ctx, cfg, testLogger(), svc, st, nil, nil, nil, &engineHelper{memHelper: newMemHelper()}); err == nil ||
		!strings.Contains(err.Error(), "no gVisor move calls") {
		t.Fatalf("a helper with no move calls: %v", err)
	}
	h := &moveEngineHelper{engineHelper: &engineHelper{memHelper: newMemHelper()}}
	w, err := wireContainerEngineWith(ctx, cfg, testLogger(), svc, st, nil, nil, nil, h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)
	if err := w.driver.DropImportedSnapshot(ctx, "sb-1"); err != nil {
		t.Fatal(err)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if !slices.Equal(h.dropped, []string{"sb-1 MOVE_SIDE_IN"}) {
		t.Fatalf("dropped %v", h.dropped)
	}
}
