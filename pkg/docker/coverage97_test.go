package docker

import (
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestBuildTagForNodeWithoutAffinity(t *testing.T) {
	plain := BuildTagFor("FROM scratch\n", nil)
	if got := BuildTagForNode("FROM scratch\n", nil, "  "); got != plain {
		t.Fatalf("blank node = %q, want %q", got, plain)
	}
	if got := BuildTagForNode("FROM scratch\n", nil, "bad id"); got != plain {
		t.Fatalf("invalid node = %q, want %q", got, plain)
	}
}

func TestCoverage97PushPortsAndReadyPath(t *testing.T) {
	c := &Client{toolboxPort: 80}
	if err := c.PushAllowedPorts(context.Background(), "", "", nil); err == nil {
		t.Fatal("empty container IP was accepted")
	}
	err := c.PushAllowedPorts(context.Background(), "bad host", "token", nil)
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("bad host = %v", err)
	}
	if c.readySocketPathOwnedByDir("/tmp/sock") {
		t.Fatal("empty ready dir owned a socket path")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.toolboxWaitTimeout = time.Second
	if err := c.pollToolboxHealthAt(ctx, "127.0.0.1:1"); err == nil {
		t.Fatal("cancelled health poll succeeded")
	}
}

func TestCoverage97ParkRejectsUnknownRuntime(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "toolbox")
	if err := os.WriteFile(bin, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	c := &Client{toolboxBinaryPath: bin, readyDir: shortReadyDir(t)}
	_, err := c.parkContainer(context.Background(), "slot", dockerpool.Key{Image: "alpine", Runtime: "nope"})
	if err == nil || !strings.Contains(err.Error(), "runtime") {
		t.Fatalf("park = %v", err)
	}
	if err := c.destroyParked(context.Background(), &dockerpool.ParkedSlot{}); err != nil {
		t.Fatal(err)
	}
}

func TestCoverage97WarmPoolReadyButUnusable(t *testing.T) {
	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	key := dockerpool.KeyFromRequest(req, models.RuntimeDocker)

	miss := &poolFakeDaemon{t: t, imageInspect: func() *http.Response {
		return textResponse(http.StatusNotFound, "missing")
	}}
	pool := dockerpool.New(nil)
	pool.RecordLoaded(&dockerpool.ParkedSlot{ID: "park-1", Key: key})
	c := newPoolClient(t, miss, func(c *Client) { c.SetWarmPool(pool) })
	if _, err := c.tryWarmAdopt(context.Background(), req, "sb", "tok", nil, models.RuntimeDocker); !errors.Is(err, dockerpool.ErrNoSlot) {
		t.Fatalf("inspect miss = %v", err)
	}

	dead := dockerpool.New(nil)
	dead.RecordLoaded(&dockerpool.ParkedSlot{ID: "park-2", Key: key})
	c = newPoolClient(t, &poolFakeDaemon{t: t}, func(c *Client) { c.SetWarmPool(dead) })
	ctx, _ := createtiming.With(context.Background())
	if _, err := c.tryWarmAdopt(ctx, req, "sb", "tok", nil, models.RuntimeDocker); !errors.Is(err, dockerpool.ErrNoSlot) {
		t.Fatalf("dead slot = %v", err)
	}

	blankDir := &poolFakeDaemon{t: t, imageInspect: func() *http.Response {
		return jsonResponse(http.StatusOK, map[string]any{
			"Id":     "sha256:img1",
			"Config": map[string]any{"Cmd": []string{"/bin/sh"}},
		})
	}}
	c = newPoolClient(t, blankDir, func(c *Client) {
		c.readyDir = shortReadyDir(t)
		c.defaultRuntime = models.RuntimeDocker
	})
	_, _ = c.parkContainer(context.Background(), "park-wd", dockerpool.Key{Image: "alpine:3.20"})
	_, _ = c.parkContainer(context.Background(), "park-rt", dockerpool.Key{Image: "alpine:3.20", Runtime: ""})
}

func TestCoverage97AdoptParkedFailures(t *testing.T) {
	pl, err := NewParkedListener(shortReadyDir(t), "slot", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })
	slot := &dockerpool.ParkedSlot{ID: "slot", ContainerID: "cid-park", ContainerIP: "10.0.0.9", Handle: pl}
	req := models.CreateSandboxRequest{Image: "alpine:3.20", CPU: models.DefaultCPU, MemoryMB: models.DefaultMemoryMB}

	denied := &poolFakeDaemon{t: t, rename: func() *http.Response {
		return textResponse(http.StatusInternalServerError, "rename failed")
	}}
	c := newPoolClient(t, denied, nil)
	if _, err := c.adoptParked(context.Background(), req, "sb", "tok", slot); err == nil {
		t.Fatal("adopt ignored a rename failure")
	}

	c = newPoolClient(t, &poolFakeDaemon{t: t, update: func() *http.Response {
		return textResponse(http.StatusInternalServerError, "update failed")
	}}, nil)
	sized := req
	sized.CPU = models.DefaultCPU + 1
	if _, err := c.adoptParked(context.Background(), sized, "sb", "tok", slot); err == nil {
		t.Fatal("adopt ignored a resource update failure")
	}

	c = newPoolClient(t, &poolFakeDaemon{t: t}, func(c *Client) { c.toolboxWaitTimeout = 20 * time.Millisecond })
	if _, err := c.adoptParked(context.Background(), req, "sb", "tok", slot); err == nil {
		t.Fatal("adopt completed without a parked connection")
	}

	ready, err := NewReadyListener(shortReadyDir(t), "sb", "token", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	// Close first. A listener whose Accept is still blocked, paired with an
	// already-cancelled context, lets both racers exit without sending and
	// waitForToolboxReadyAt blocks on the result channel forever.
	_ = ready.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := c.waitForToolboxReadyAt(ctx, "127.0.0.1:1", ready); err == nil {
		t.Fatal("toolbox wait succeeded after the ready listener was closed")
	}
}
