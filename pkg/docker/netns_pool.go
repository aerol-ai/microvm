package docker

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// The pause-netns pool pre-pays dockerd's per-container network setup
// (veth pair, bridge attach, IPAM, iptables — the slowest and most
// concurrency-hostile part of a cold create, since all iptables changes
// serialize on the kernel's xtables lock). Each slot is a started pause
// container that exists only to hold a network namespace; a sandbox
// create of ANY image adopts one via NetworkMode container:<id>, so the
// pool works regardless of image spread — unlike the per-image warm
// pool, which it composes with (warm-pool adopt is tried first and
// skips this pool entirely).
//
// Ownership protocol is rename-first: a slot is renamed to the adopted
// name BEFORE the sandbox container is created, so a crash between the
// two leaves an adopted-named pause with no sandbox — the reap loop
// detects exactly that pattern and removes it. Labels can't be used for
// ownership because Docker labels are immutable after create.

const (
	// netnsPauseLabelKey marks pause containers. Deliberately NOT
	// managedLabelKey: pause containers must stay invisible to
	// ListManaged / zombie GC / ready-socket sweeps, all of which
	// filter on the managed label.
	netnsPauseLabelKey = "aerolvm.netns-pause"

	// Free slots are named netnsFreePrefix<random>; adopted slots are
	// named netnsAdoptedPrefix<sandboxID>. The adopted name is what ties
	// a pause container to its sandbox for destroy-time cleanup and
	// crash reconciliation.
	netnsFreePrefix    = "aerolvm-netns-"
	netnsAdoptedPrefix = "aerolvm-netns-sb-"
)

func netnsAdoptedName(sandboxID string) string {
	return netnsAdoptedPrefix + sandboxID
}

type netnsSlot struct {
	containerID string
	ip          string
}

// NetnsPool keeps DockerNetnsPoolDepth pause containers warm and hands
// them to Create. All docker calls go through the owning Client.
type NetnsPool struct {
	logger     *slog.Logger
	client     *Client
	depth      int
	pauseImage string
	interval   time.Duration

	mu   sync.Mutex
	free []netnsSlot

	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

func newNetnsPool(logger *slog.Logger, client *Client, depth int, pauseImage string, interval time.Duration) *NetnsPool {
	if depth <= 0 {
		depth = 4
	}
	if interval <= 0 {
		interval = 2 * time.Second
	}
	return &NetnsPool{
		logger:     logger,
		client:     client,
		depth:      depth,
		pauseImage: strings.TrimSpace(pauseImage),
		interval:   interval,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
}

// StartNetnsPool wires and starts the pause-netns pool on the client.
// Call once at daemon boot; no-op protection is the caller's problem
// (daemon wiring runs it once behind the config gate).
func (c *Client) StartNetnsPool(ctx context.Context, logger *slog.Logger, depth int, pauseImage string, interval time.Duration) *NetnsPool {
	p := newNetnsPool(logger, c, depth, pauseImage, interval)
	c.netnsPool = p
	go p.run(ctx)
	return p
}

// Stop halts the refill loop and removes all free slots. Adopted slots
// belong to their sandboxes and are cleaned up by Destroy.
func (p *NetnsPool) Stop(ctx context.Context) {
	p.stopOnce.Do(func() { close(p.stopCh) })
	<-p.doneCh
	p.mu.Lock()
	free := p.free
	p.free = nil
	p.mu.Unlock()
	for _, slot := range free {
		_ = p.client.removeContainer(ctx, slot.containerID, true)
	}
}

func (p *NetnsPool) run(ctx context.Context) {
	defer close(p.doneCh)
	// Adopt survivors from a previous daemon run before the first refill
	// so a restart doesn't stack a second fleet of pause containers on
	// top of the old one.
	p.reconcile(ctx)
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		p.refill(ctx)
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		case <-ticker.C:
		}
	}
}

// reconcile adopts leftover free slots from a previous run and removes
// adopted-named pauses whose sandbox container no longer exists (the
// crash window between rename and sandbox create, or a destroy that
// died halfway).
func (p *NetnsPool) reconcile(ctx context.Context) {
	summaries, err := p.client.listNetnsPauseContainers(ctx)
	if err != nil {
		p.logger.Warn("netns pool reconcile list failed", "error", err)
		return
	}
	for _, s := range summaries {
		name := containerSummaryName(s)
		switch {
		case strings.HasPrefix(name, netnsAdoptedPrefix):
			sandboxID := strings.TrimPrefix(name, netnsAdoptedPrefix)
			if _, err := p.client.inspectContainer(ctx, sandboxID); err != nil {
				netnsPoolOrphansReaped.Add(1)
				_ = p.client.removeContainer(ctx, s.ID, true)
			}
		case strings.HasPrefix(name, netnsFreePrefix):
			inspect, err := p.client.inspectContainer(ctx, s.ID)
			ip := getContainerIP(inspect, p.client.network)
			if err != nil || inspect.State == nil || !inspect.State.Running || ip == "" {
				_ = p.client.removeContainer(ctx, s.ID, true)
				continue
			}
			p.mu.Lock()
			p.free = append(p.free, netnsSlot{containerID: inspect.ID, ip: ip})
			p.mu.Unlock()
		}
	}
	netnsPoolSize.Set(int64(p.size()))
}

func (p *NetnsPool) size() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.free)
}

func (p *NetnsPool) refill(ctx context.Context) {
	for p.size() < p.depth {
		select {
		case <-ctx.Done():
			return
		case <-p.stopCh:
			return
		default:
		}
		slot, err := p.spawnPause(ctx)
		if err != nil {
			netnsPoolRefillErrors.Add(1)
			p.logger.Warn("netns pool refill failed", "error", err)
			return // back off until the next tick rather than hot-looping
		}
		p.mu.Lock()
		p.free = append(p.free, slot)
		p.mu.Unlock()
		netnsPoolSize.Set(int64(p.size()))
	}
}

func (p *NetnsPool) spawnPause(ctx context.Context) (netnsSlot, error) {
	if p.pauseImage == "" {
		return netnsSlot{}, fmt.Errorf("netns pool: pause image is not configured")
	}
	// Image work happens here, on the refill goroutine — never on the
	// create path. One inspect when warm; a pull only on first use.
	if _, err := p.client.inspectImage(ctx, p.pauseImage); err != nil {
		if pullErr := p.client.pullImageDedup(ctx, p.pauseImage, nil); pullErr != nil {
			return netnsSlot{}, fmt.Errorf("pull pause image: %w", pullErr)
		}
	}

	suffix := make([]byte, 6)
	if _, err := rand.Read(suffix); err != nil {
		return netnsSlot{}, err
	}
	name := netnsFreePrefix + hex.EncodeToString(suffix)

	createRequest := map[string]any{
		"Image":  p.pauseImage,
		"Labels": map[string]string{netnsPauseLabelKey: "true"},
	}
	hostConfig := map[string]any{}
	if p.client.network != "" && p.client.network != "bridge" {
		hostConfig["NetworkMode"] = p.client.network
	}
	createRequest["HostConfig"] = hostConfig

	var created struct {
		ID string `json:"Id"`
	}
	q := url.Values{}
	q.Set("name", name)
	if err := p.client.doJSON(ctx, http.MethodPost, "/containers/create", q, createRequest, nil, &created); err != nil {
		return netnsSlot{}, fmt.Errorf("create pause container: %w", err)
	}
	if err := p.client.doJSON(ctx, http.MethodPost, "/containers/"+url.PathEscape(created.ID)+"/start", nil, nil, nil, nil); err != nil {
		_ = p.client.removeContainer(ctx, created.ID, true)
		return netnsSlot{}, fmt.Errorf("start pause container: %w", err)
	}
	inspect, err := p.client.inspectContainer(ctx, created.ID)
	ip := getContainerIP(inspect, p.client.network)
	if err != nil || ip == "" {
		_ = p.client.removeContainer(ctx, created.ID, true)
		if err == nil {
			err = fmt.Errorf("pause container %s has no IP", created.ID)
		}
		return netnsSlot{}, err
	}
	return netnsSlot{containerID: created.ID, ip: ip}, nil
}

// Adopt pops a warm slot and renames it to the sandbox's adopted name.
// The rename doubles as the liveness check — it fails if the pause died
// — and establishes crash-safe ownership before the sandbox container
// exists. Returns ok=false on any miss; the caller falls back to the
// plain cold path.
func (p *NetnsPool) Adopt(ctx context.Context, sandboxID string) (netnsSlot, bool) {
	for {
		p.mu.Lock()
		if len(p.free) == 0 {
			p.mu.Unlock()
			netnsPoolMisses.Add(1)
			return netnsSlot{}, false
		}
		slot := p.free[len(p.free)-1]
		p.free = p.free[:len(p.free)-1]
		p.mu.Unlock()
		netnsPoolSize.Set(int64(p.size()))

		if err := p.client.renameContainer(ctx, slot.containerID, netnsAdoptedName(sandboxID)); err != nil {
			// Dead or vanished slot: drop it and try the next one.
			_ = p.client.removeContainer(ctx, slot.containerID, true)
			continue
		}
		netnsPoolHits.Add(1)
		return slot, true
	}
}

// ReleaseAdopted removes an adopted pause container after the sandbox
// create failed downstream of Adopt. The slot can't be returned to the
// pool: it already carries the sandbox's adopted name, and a rename
// back would race a concurrent duplicate create for the same ID.
func (p *NetnsPool) ReleaseAdopted(ctx context.Context, slot netnsSlot) {
	_ = p.client.removeContainer(ctx, slot.containerID, true)
}

// removeNetnsPauseForSandbox is the destroy-path cleanup: best-effort
// removal of the sandbox's adopted pause container by name. 404 means
// the sandbox never had one (pool disabled, warm-pool adopt, or old
// sandbox) — a no-op by design.
func (c *Client) removeNetnsPauseForSandbox(ctx context.Context, sandboxID string) {
	sandboxID = strings.TrimSpace(sandboxID)
	if sandboxID == "" {
		return
	}
	// removeContainer already treats 404 as success, so a sandbox that never
	// adopted a pause slot (pool disabled, warm-pool hit) is a silent no-op.
	if err := c.removeContainer(ctx, netnsAdoptedName(sandboxID), true); err != nil {
		c.logger.Warn("remove netns pause container failed", "sandbox_id", sandboxID, "error", err)
	}
}

func (c *Client) listNetnsPauseContainers(ctx context.Context) ([]containerSummary, error) {
	filters := fmt.Sprintf(`{"label":["%s=true"]}`, netnsPauseLabelKey)
	q := queryValues(map[string]string{"all": "1", "filters": filters})
	var out []containerSummary
	if err := c.doJSON(ctx, http.MethodGet, "/containers/json", q, nil, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func containerSummaryName(s containerSummary) string {
	for _, n := range s.Names {
		return strings.TrimPrefix(n, "/")
	}
	return ""
}
