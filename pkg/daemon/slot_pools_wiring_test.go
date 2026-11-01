package daemon

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	cntr "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/pkg/capacity"
)

type slotProviderRecorder struct {
	fn func() []capacity.SlotPool
}

func (r *slotProviderRecorder) SetLocalSlotPoolsProvider(fn func() []capacity.SlotPool) { r.fn = fn }

func TestRegisterSlotPoolsProvider(t *testing.T) {
	pools := func(context.Context) []capacity.SlotPool {
		return []capacity.SlotPool{{Name: capacity.SlotPoolContainerNetns, Free: 7}}
	}
	worker := config.Config{NodeRole: config.NodeRoleWorker}

	rec := &slotProviderRecorder{}
	registerSlotPoolsProvider(worker, rec, pools)
	if rec.fn == nil || rec.fn()[0].Free != 7 {
		t.Fatal("a worker's cluster client must get the slot pool provider")
	}

	server := &slotProviderRecorder{}
	registerSlotPoolsProvider(config.Config{NodeRole: config.NodeRoleServer}, server, pools)
	if server.fn != nil {
		t.Fatal("a node that cannot own sandboxes has no pools to advertise")
	}
	// A client without the hook and a nil source are both left alone.
	registerSlotPoolsProvider(worker, struct{}{}, pools)
	none := &slotProviderRecorder{}
	registerSlotPoolsProvider(worker, none, nil)
	if none.fn != nil {
		t.Fatal("nil pool source must not register a provider")
	}
}

// A pool bigger than one bridge can hold is a configuration the operator
// must hear about at boot: the slots past 1023 can never be realized.
func TestWireContainerdNativeNetnsPoolWarnsPastBridgeLimit(t *testing.T) {
	for _, tc := range []struct {
		size int
		warn bool
	}{{maxBridgePorts, false}, {maxBridgePorts + 1, true}} {
		var buf bytes.Buffer
		logger := slog.New(slog.NewTextHandler(&buf, nil))
		cfg := config.Config{
			ContainerEngine:                  "containerd",
			ContainerdNativeNetnsPoolEnabled: true,
			ContainerdNetnsPoolDepth:         4,
			ContainerdNetnsPoolSize:          tc.size,
		}
		driver := cntr.New(cntr.FromDaemonConfig(cfg), nil, testLogger())
		// Empty CNI paths fail the wiring after the warning and the seed.
		if pool, err := wireContainerdNativeNetnsPool(context.Background(), cfg, logger, openDaemonTestStore(t), driver); err == nil {
			if pool != nil {
				pool.Stop()
			}
			t.Fatal("want cni config error (empty CNI paths)")
		}
		if got := strings.Contains(buf.String(), "bridge_port_limit"); got != tc.warn {
			t.Fatalf("size %d: warned=%t, want %t; log=%s", tc.size, got, tc.warn, buf.String())
		}
	}
}
