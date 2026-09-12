package docker

import (
	"context"
	"log/slog"
	"net/http"
	"testing"
	"time"
)

func TestCoverage95NetnsPoolSpawnAndAdopt(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	c := newPoolClient(t, d, func(c *Client) { c.network = "custom-net" })
	pool := newNetnsPool(slogDefault(), c, 1, "pause:latest", time.Second)
	slot, err := pool.spawnPause(context.Background())
	if err != nil {
		t.Fatalf("spawnPause: %v", err)
	}
	if slot.containerID != "cid-park" || slot.ip != "172.17.0.9" {
		t.Fatalf("spawned slot = %+v", slot)
	}
	pool.free = append(pool.free, slot)
	adopted, ok := pool.Adopt(context.Background(), "sandbox")
	if !ok || adopted.containerID != slot.containerID {
		t.Fatalf("Adopt() = %+v, %v", adopted, ok)
	}
	if _, ok := pool.Adopt(context.Background(), "other"); ok {
		t.Fatal("empty pool unexpectedly adopted a slot")
	}
	pool.ReleaseAdopted(context.Background(), adopted)
}

func TestCoverage95RemoveNetnsPausePaths(t *testing.T) {
	c := &Client{logger: slog.Default()}
	c.removeNetnsPauseForSandbox(context.Background(), "")
	c.removeNetnsPauseForSandbox(context.Background(), "   ")

	d := newNetnsFakeDaemon()
	client := newNetnsClient(t, d)
	client.logger = slog.Default()
	client.removeNetnsPauseForSandbox(context.Background(), "sb-missing")

	d.mu.Lock()
	d.containers["pause-err"] = &netnsFakeContainer{id: "pause-err", name: netnsAdoptedName("sb-err")}
	d.mu.Unlock()
	client.httpClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == http.MethodDelete {
			return textResponse(http.StatusInternalServerError, "remove failed"), nil
		}
		return d.transport()(r)
	})}
	client.removeNetnsPauseForSandbox(context.Background(), "sb-err")
}

func TestCoverage95NetnsPoolRefillCancellation(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsClient(t, d)
	p := newTestNetnsPool(c, 2)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p.refill(ctx)

	stopCh := make(chan struct{})
	close(stopCh)
	p.stopCh = stopCh
	p.refill(context.Background())
}
