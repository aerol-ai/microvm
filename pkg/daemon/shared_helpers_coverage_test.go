package daemon

import (
	"context"
	"testing"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/models"
)

type stubParkHandle struct{ alive bool }

func (h *stubParkHandle) Alive() bool { return h.alive }

func (h *stubParkHandle) Adopt(context.Context, string, string, string) error { return nil }

func (h *stubParkHandle) Close() error { return nil }

func poolWithLoadedSlot(t *testing.T) *dockerpool.Pool {
	t.Helper()
	p := dockerpool.New(testLogger())
	key := dockerpool.Key{Image: "alpine:3.20", Runtime: models.RuntimeDocker}
	p.RecordLoaded(&dockerpool.ParkedSlot{
		ID: "park-drain", Key: key, Handle: &stubParkHandle{alive: true},
	})
	return p
}
