package docker

import (
	"context"
	"net/http"
	"testing"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestParkContainerCreateFailureCleansListener(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	d.create = func() *http.Response { return textResponse(http.StatusInternalServerError, "fail") }
	c := newPoolClient(t, d, nil)
	_, err := c.parkContainer(context.Background(), "park-fail", dockerpool.Key{Image: "i", Runtime: models.RuntimeDocker})
	if err == nil {
		t.Fatal("expected park failure")
	}
}

func TestPoolSpawnerDestroyParkedWired(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	c := newPoolClient(t, d, nil)
	sp := &PoolSpawner{Client: c}
	if err := sp.DestroyParked(context.Background(), &dockerpool.ParkedSlot{ContainerID: "cid"}); err != nil {
		t.Fatal(err)
	}
}
