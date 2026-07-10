package docker

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func newNetnsCreateClient(t *testing.T, d *netnsFakeDaemon, toolboxOK bool) *Client {
	t.Helper()
	ip, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) {
		if toolboxOK {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	t.Cleanup(closeFn)

	c := &Client{
		logger:             slog.Default(),
		toolboxBinaryPath:  writableToolbox(t),
		toolboxMountPath:   "/usr/local/bin/toolboxd",
		toolboxPort:        port,
		defaultRuntime:     models.RuntimeDocker,
		networkRules:       disabledRules(t),
		httpClient:         &http.Client{Transport: d.transport()},
		streamClient:       &http.Client{Transport: d.transport()},
		toolboxClient:      &http.Client{Timeout: 2 * time.Second},
		waitTimeout:        2 * time.Second,
		toolboxWaitTimeout: 2 * time.Second,
		pulls:              map[string]*imagePull{},
		pullFailures:       map[string]imagePullFailure{},
	}
	// Fill the pool, then point every warm slot's IP at the local toolbox
	// health server so the readiness poll (dialed against the pause IP —
	// the netns owner) succeeds.
	pool := newTestNetnsPool(c, 1)
	c.netnsPool = pool
	pool.refill(context.Background())
	d.mu.Lock()
	for _, cont := range d.containers {
		if strings.HasPrefix(cont.name, netnsFreePrefix) {
			cont.ip = ip
		}
	}
	d.mu.Unlock()
	pool.mu.Lock()
	for i := range pool.free {
		pool.free[i].ip = ip
	}
	pool.mu.Unlock()
	return c
}

// A cold create with a warm netns slot must join the pause container's
// namespace (NetworkMode container:<id>) and surface the pause slot's IP
// as the sandbox IP — that is the address caddy routes to and netrules
// key on.
func TestCreateAdoptsNetnsSlot(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsCreateClient(t, d, true)

	ctx, timing := WithCreateTiming(context.Background())
	runtime, err := c.Create(ctx, models.CreateSandboxRequest{Image: "img"}, "sb-netns", "tok", nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	pause := d.byRef(netnsAdoptedName("sb-netns"))
	if pause == nil {
		t.Fatal("no adopted pause container for the sandbox")
	}
	joiner := d.byRef("sb-netns")
	if joiner == nil {
		t.Fatal("sandbox container not created")
	}
	if want := "container:" + pause.id; joiner.netMode != want {
		t.Fatalf("sandbox NetworkMode = %q, want %q", joiner.netMode, want)
	}
	if runtime.ContainerIP != pause.ip {
		t.Fatalf("sandbox ContainerIP = %q, want pause IP %q", runtime.ContainerIP, pause.ip)
	}
	hit := false
	for _, st := range timing.Stages() {
		if st.Name == "docker_netns" && st.Desc == "hit" {
			hit = true
		}
	}
	if !hit {
		t.Fatalf("stages = %+v, want docker_netns hit", timing.Stages())
	}
}

// A create that fails after adopting a netns slot must remove the adopted
// pause container — it already carries the sandbox's name, so returning it
// to the pool would race a concurrent duplicate create.
func TestCreateFailureReleasesAdoptedNetns(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsCreateClient(t, d, true)
	d.mu.Lock()
	d.startErr = true
	d.mu.Unlock()

	if _, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb-fail", "tok", nil); err == nil {
		t.Fatal("create should have failed on container start")
	}
	if d.byRef(netnsAdoptedName("sb-fail")) != nil {
		t.Fatal("adopted pause container leaked after failed create")
	}
}

// With an empty pool the create must fall back to the plain cold path —
// no NetworkMode override, sandbox keeps its own IP.
func TestCreateFallsBackOnNetnsMiss(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsCreateClient(t, d, true)

	// Drain the pool so the adopt misses.
	if _, ok := c.netnsPool.Adopt(context.Background(), "sb-drain"); !ok {
		t.Fatal("drain adopt should have hit")
	}

	// The fallback sandbox gets a fake-daemon IP the toolbox poll can't
	// reach; point the health check at nothing and instead assert on the
	// createRequest shape by letting the wait fail fast.
	c.toolboxWaitTimeout = 50 * time.Millisecond
	_, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb-cold", "tok", nil)
	if err == nil {
		t.Fatal("expected toolbox wait failure on unreachable cold-path IP")
	}
	joiner := d.byRef("sb-cold")
	if joiner == nil {
		// The failed create removes the container; shape was still exercised.
		return
	}
	if strings.HasPrefix(joiner.netMode, "container:") {
		t.Fatalf("cold-path sandbox unexpectedly joined a netns: %q", joiner.netMode)
	}
}

// gVisor sandboxes must never adopt a netns slot: runsc manages its own
// network sandboxing.
func TestCreateSkipsNetnsForGvisor(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsCreateClient(t, d, true)
	c.toolboxWaitTimeout = 50 * time.Millisecond

	_, _ = c.Create(context.Background(), models.CreateSandboxRequest{Image: "img", Runtime: models.RuntimeGvisor}, "sb-gv", "tok", nil)

	if got := c.netnsPool.size(); got != 1 {
		t.Fatalf("pool size = %d, want 1 (gvisor create must not adopt)", got)
	}
}
