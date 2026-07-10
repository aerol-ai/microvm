package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// netnsFakeDaemon is a docker-API stub for the pause-netns pool: it tracks a
// live container table so create/rename/remove/list/inspect stay consistent
// across calls, which the pool's reconcile and adopt paths depend on.
type netnsFakeDaemon struct {
	mu           sync.Mutex
	nextID       int
	containers   map[string]*netnsFakeContainer // by ID
	startErr     bool
	listErr      bool
	imageMissing bool // pause image absent until a pull lands
	noIP         bool // created containers report no IP
	pullCalls    int
	requests     []string
}

type netnsFakeContainer struct {
	id      string
	name    string
	labels  map[string]string
	running bool
	ip      string
	netMode string
}

func newNetnsFakeDaemon() *netnsFakeDaemon {
	return &netnsFakeDaemon{containers: map[string]*netnsFakeContainer{}}
}

func (d *netnsFakeDaemon) add(c *netnsFakeContainer) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.containers[c.id] = c
}

func (d *netnsFakeDaemon) byRef(ref string) *netnsFakeContainer {
	for _, c := range d.containers {
		if c.id == ref || c.name == ref {
			return c
		}
	}
	return nil
}

func (d *netnsFakeDaemon) inspectJSON(c *netnsFakeContainer) string {
	networks := "{}"
	if c.ip != "" {
		networks = fmt.Sprintf(`{"bridge":{"IPAddress":%q}}`, c.ip)
	}
	return fmt.Sprintf(`{
		"Id": %q, "Name": %q,
		"State": {"Running": %v, "Status": "running", "Pid": 7},
		"NetworkSettings": {"Networks": %s},
		"HostConfig": {"NetworkMode": %q}
	}`, c.id, "/"+c.name, c.running, networks, c.netMode)
}

func (d *netnsFakeDaemon) transport() roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		p := r.URL.Path
		d.requests = append(d.requests, r.Method+" "+p)
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(p, "/images/"):
			if d.imageMissing {
				return textResponse(http.StatusNotFound, `{"message":"No such image"}`), nil
			}
			return jsonResponse(http.StatusOK, map[string]any{"Id": "pauseimg"}), nil
		case r.Method == http.MethodPost && p == "/images/create":
			d.pullCalls++
			d.imageMissing = false
			return textResponse(http.StatusOK, "{}"), nil
		case r.Method == http.MethodPost && p == "/containers/create":
			var body struct {
				Labels     map[string]string `json:"Labels"`
				HostConfig struct {
					NetworkMode string `json:"NetworkMode"`
				} `json:"HostConfig"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			d.nextID++
			id := fmt.Sprintf("pause-%d", d.nextID)
			ip := fmt.Sprintf("172.30.0.%d", d.nextID)
			// Docker realism: a container joined to another's netns has no
			// NetworkSettings of its own — the IP belongs to the owner.
			if strings.HasPrefix(body.HostConfig.NetworkMode, "container:") {
				ip = ""
			}
			if d.noIP {
				ip = ""
			}
			d.containers[id] = &netnsFakeContainer{
				id:      id,
				name:    r.URL.Query().Get("name"),
				labels:  body.Labels,
				ip:      ip,
				netMode: body.HostConfig.NetworkMode,
			}
			return jsonResponse(http.StatusCreated, map[string]string{"Id": id}), nil
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/start"):
			if d.startErr {
				return textResponse(http.StatusInternalServerError, "start failed"), nil
			}
			ref := strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/start")
			if c := d.byRef(ref); c != nil {
				c.running = true
			}
			return textResponse(http.StatusNoContent, ""), nil
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/rename"):
			ref := strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/rename")
			c := d.byRef(ref)
			if c == nil || !c.running {
				return textResponse(http.StatusNotFound, "no such container"), nil
			}
			c.name = r.URL.Query().Get("name")
			return textResponse(http.StatusNoContent, ""), nil
		case r.Method == http.MethodGet && p == "/containers/json":
			if d.listErr {
				return textResponse(http.StatusInternalServerError, "list failed"), nil
			}
			out := make([]map[string]any, 0, len(d.containers))
			for _, c := range d.containers {
				out = append(out, map[string]any{
					"Id": c.id, "Names": []string{"/" + c.name}, "Labels": c.labels,
				})
			}
			return jsonResponse(http.StatusOK, out), nil
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/json"):
			ref := strings.TrimSuffix(strings.TrimPrefix(p, "/containers/"), "/json")
			c := d.byRef(ref)
			if c == nil {
				return textResponse(http.StatusNotFound, "no such container"), nil
			}
			return textResponse(http.StatusOK, d.inspectJSON(c)), nil
		case r.Method == http.MethodDelete && strings.HasPrefix(p, "/containers/"):
			ref := strings.TrimPrefix(p, "/containers/")
			c := d.byRef(ref)
			if c == nil {
				return textResponse(http.StatusNotFound, "no such container"), nil
			}
			delete(d.containers, c.id)
			return textResponse(http.StatusNoContent, ""), nil
		}
		return textResponse(http.StatusNotFound, "no such endpoint: "+r.Method+" "+p), nil
	}
}

func newNetnsClient(t *testing.T, d *netnsFakeDaemon) *Client {
	t.Helper()
	return &Client{
		logger:       slog.Default(),
		httpClient:   &http.Client{Transport: d.transport()},
		streamClient: &http.Client{Transport: d.transport()},
		pulls:        map[string]*imagePull{},
		pullFailures: map[string]imagePullFailure{},
	}
}

func newTestNetnsPool(c *Client, depth int) *NetnsPool {
	return newNetnsPool(slog.Default(), c, depth, "pause:test", time.Second)
}

func (d *netnsFakeDaemon) countWithPrefix(prefix string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, c := range d.containers {
		if strings.HasPrefix(c.name, prefix) {
			n++
		}
	}
	return n
}

func TestNetnsPoolRefillToDepth(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsClient(t, d)
	p := newTestNetnsPool(c, 3)

	p.refill(context.Background())

	if got := p.size(); got != 3 {
		t.Fatalf("pool size = %d, want 3", got)
	}
	if got := d.countWithPrefix(netnsFreePrefix); got != 3 {
		t.Fatalf("pause containers = %d, want 3", got)
	}
	d.mu.Lock()
	for _, cont := range d.containers {
		if cont.labels[netnsPauseLabelKey] != "true" {
			t.Fatalf("pause container %s missing %s label", cont.id, netnsPauseLabelKey)
		}
		if cont.labels[managedLabelKey] != "" {
			t.Fatalf("pause container %s must not carry the managed label", cont.id)
		}
		if !cont.running {
			t.Fatalf("pause container %s not started", cont.id)
		}
	}
	d.mu.Unlock()
}

func TestNetnsPoolAdoptRenamesAndPops(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsClient(t, d)
	p := newTestNetnsPool(c, 1)
	p.refill(context.Background())

	slot, ok := p.Adopt(context.Background(), "sb-adopt")
	if !ok {
		t.Fatal("Adopt returned miss with a warm slot available")
	}
	if slot.ip == "" {
		t.Fatal("adopted slot has no IP")
	}
	if got := d.byRef(netnsAdoptedName("sb-adopt")); got == nil {
		t.Fatal("adopted pause container was not renamed to the sandbox-owned name")
	}
	if _, ok := p.Adopt(context.Background(), "sb-other"); ok {
		t.Fatal("Adopt returned a slot from an empty pool")
	}
}

func TestNetnsPoolAdoptSkipsDeadSlot(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsClient(t, d)
	p := newTestNetnsPool(c, 2)
	p.refill(context.Background())

	// Kill the slot at the top of the stack; Adopt must drop it (rename
	// fails) and fall through to the live one.
	p.mu.Lock()
	top := p.free[len(p.free)-1]
	p.mu.Unlock()
	d.mu.Lock()
	d.containers[top.containerID].running = false
	d.mu.Unlock()

	slot, ok := p.Adopt(context.Background(), "sb-live")
	if !ok {
		t.Fatal("Adopt missed despite one live slot")
	}
	if slot.containerID == top.containerID {
		t.Fatal("Adopt handed out the dead slot")
	}
	if d.byRef(top.containerID) != nil {
		t.Fatal("dead slot was not removed")
	}
}

func TestNetnsPoolReconcileAdoptsSurvivorsAndReapsOrphans(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsClient(t, d)

	// Survivor free slot from a previous run.
	d.add(&netnsFakeContainer{
		id: "old-free", name: netnsFreePrefix + "aaaa", running: true, ip: "172.30.9.1",
		labels: map[string]string{netnsPauseLabelKey: "true"},
	})
	// Adopted pause whose sandbox is gone — the crash window artifact.
	d.add(&netnsFakeContainer{
		id: "orphan", name: netnsAdoptedName("sb-dead"), running: true, ip: "172.30.9.2",
		labels: map[string]string{netnsPauseLabelKey: "true"},
	})
	// Adopted pause whose sandbox container still exists — must be kept.
	d.add(&netnsFakeContainer{
		id: "kept", name: netnsAdoptedName("sb-alive"), running: true, ip: "172.30.9.3",
		labels: map[string]string{netnsPauseLabelKey: "true"},
	})
	d.add(&netnsFakeContainer{id: "sb-c", name: "sb-alive", running: true, ip: "172.30.9.4"})

	p := newTestNetnsPool(c, 4)
	p.reconcile(context.Background())

	if got := p.size(); got != 1 {
		t.Fatalf("pool size after reconcile = %d, want 1 survivor", got)
	}
	if d.byRef("orphan") != nil {
		t.Fatal("orphaned adopted pause was not reaped")
	}
	if d.byRef("kept") == nil {
		t.Fatal("adopted pause with a live sandbox was wrongly reaped")
	}
}

func TestNetnsPoolStopRemovesFreeSlots(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsClient(t, d)
	p := newTestNetnsPool(c, 2)
	p.refill(context.Background())
	close(p.doneCh) // run() never started in this test

	p.Stop(context.Background())
	if got := d.countWithPrefix(netnsFreePrefix); got != 0 {
		t.Fatalf("free pause containers after Stop = %d, want 0", got)
	}
}

func TestNetnsPoolStartRunAndStop(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsClient(t, d)

	pool := c.StartNetnsPool(context.Background(), slog.Default(), 2, "pause:test", 10*time.Millisecond)
	deadline := time.Now().Add(5 * time.Second)
	for pool.size() < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if pool.size() != 2 {
		t.Fatalf("pool never refilled: size = %d", pool.size())
	}
	if c.netnsPool != pool {
		t.Fatal("StartNetnsPool did not wire the pool onto the client")
	}
	pool.Stop(context.Background())
	if got := d.countWithPrefix(netnsFreePrefix); got != 0 {
		t.Fatalf("free pause containers after Stop = %d, want 0", got)
	}
}

func TestNetnsPoolRefillBacksOffOnError(t *testing.T) {
	d := newNetnsFakeDaemon()
	d.startErr = true
	c := newNetnsClient(t, d)
	p := newTestNetnsPool(c, 3)

	before := netnsPoolRefillErrors.Value()
	p.refill(context.Background())
	if got := p.size(); got != 0 {
		t.Fatalf("pool size = %d, want 0 on spawn failure", got)
	}
	// One error then back off until the next tick — not depth× errors.
	if netnsPoolRefillErrors.Value() != before+1 {
		t.Fatalf("refill errors = %d, want %d", netnsPoolRefillErrors.Value(), before+1)
	}
	if got := d.countWithPrefix(netnsFreePrefix); got != 0 {
		t.Fatalf("failed pause containers not cleaned up: %d left", got)
	}
}

func TestNetnsPoolSpawnRequiresPauseImage(t *testing.T) {
	c := newNetnsClient(t, newNetnsFakeDaemon())
	p := newNetnsPool(slog.Default(), c, 1, "  ", time.Second)
	if _, err := p.spawnPause(context.Background()); err == nil {
		t.Fatal("spawnPause should fail without a configured pause image")
	}
}

func TestDestroyRemovesAdoptedPause(t *testing.T) {
	d := newNetnsFakeDaemon()
	c := newNetnsClient(t, d)
	c.networkRules = disabledRules(t)

	d.add(&netnsFakeContainer{id: "sb-ctr", name: "sb-gone", running: true})
	d.add(&netnsFakeContainer{
		id: "pause-x", name: netnsAdoptedName("sb-gone"), running: true,
		labels: map[string]string{netnsPauseLabelKey: "true"},
	})

	err := c.Destroy(context.Background(), &models.Sandbox{ID: "sb-gone", ContainerID: "sb-ctr"})
	if err != nil {
		t.Fatalf("Destroy: %v", err)
	}
	if d.byRef("pause-x") != nil {
		t.Fatal("Destroy did not remove the adopted pause container")
	}
	if d.byRef("sb-ctr") != nil {
		t.Fatal("Destroy did not remove the sandbox container")
	}
}

func TestNewNetnsPoolDefaults(t *testing.T) {
	p := newNetnsPool(slog.Default(), nil, 0, "  pause:img  ", 0)
	if p.depth != 4 {
		t.Fatalf("depth = %d, want default 4", p.depth)
	}
	if p.interval != 2*time.Second {
		t.Fatalf("interval = %v, want default 2s", p.interval)
	}
	if p.pauseImage != "pause:img" {
		t.Fatalf("pauseImage = %q, want trimmed", p.pauseImage)
	}
}

// A fresh host has no pause image: spawnPause must pull it once (on the
// refill goroutine, off the create path) instead of failing every tick —
// the same self-warming contract the park pool's spawner has.
func TestNetnsSpawnPausePullsMissingImage(t *testing.T) {
	d := newNetnsFakeDaemon()
	d.imageMissing = true
	c := newNetnsClient(t, d)
	p := newTestNetnsPool(c, 1)

	slot, err := p.spawnPause(context.Background())
	if err != nil {
		t.Fatalf("spawnPause: %v", err)
	}
	if slot.containerID == "" || slot.ip == "" {
		t.Fatalf("slot = %+v", slot)
	}
	if d.pullCalls != 1 {
		t.Fatalf("pull calls = %d, want 1", d.pullCalls)
	}
}

// Failure after the pause container exists must remove it — a leaked pause
// holds a bridge IP and pollutes the next reconcile's inventory.
func TestNetnsSpawnPauseFailureRemovesContainer(t *testing.T) {
	t.Run("start fails", func(t *testing.T) {
		d := newNetnsFakeDaemon()
		d.startErr = true
		c := newNetnsClient(t, d)
		p := newTestNetnsPool(c, 1)

		if _, err := p.spawnPause(context.Background()); err == nil ||
			!strings.Contains(err.Error(), "start pause container") {
			t.Fatalf("err = %v, want start failure", err)
		}
		if n := len(d.containers); n != 0 {
			t.Fatalf("leaked pause containers: %d", n)
		}
	})

	t.Run("no IP", func(t *testing.T) {
		d := newNetnsFakeDaemon()
		d.noIP = true
		c := newNetnsClient(t, d)
		p := newTestNetnsPool(c, 1)

		if _, err := p.spawnPause(context.Background()); err == nil ||
			!strings.Contains(err.Error(), "no IP") {
			t.Fatalf("err = %v, want no-IP failure", err)
		}
		if n := len(d.containers); n != 0 {
			t.Fatalf("leaked pause containers: %d", n)
		}
	})
}

// Reconcile must keep an adopted pause whose sandbox is alive (that netns is
// in use!) and must survive a transient list failure without touching state.
func TestNetnsPoolReconcileKeepsLiveAdoptedAndSurvivesListError(t *testing.T) {
	d := newNetnsFakeDaemon()
	// Adopted pause + its living sandbox container.
	d.add(&netnsFakeContainer{
		id: "pause-live", name: netnsAdoptedName("sb-live"), running: true,
		ip: "172.30.0.8", labels: map[string]string{netnsPauseLabelKey: "true"},
	})
	d.add(&netnsFakeContainer{id: "cid-live", name: "sb-live", running: true, ip: "172.30.0.9"})
	c := newNetnsClient(t, d)
	p := newTestNetnsPool(c, 1)

	p.reconcile(context.Background())
	if d.byRef("pause-live") == nil {
		t.Fatal("reconcile reaped the pause of a LIVE sandbox — its netns is in use")
	}
	if p.size() != 0 {
		t.Fatalf("adopted pause must not enter the free list: size=%d", p.size())
	}

	d.listErr = true
	p.reconcile(context.Background()) // must not panic or mutate
	if d.byRef("pause-live") == nil || p.size() != 0 {
		t.Fatal("state changed under a list error")
	}
}

func TestContainerSummaryNameEmpty(t *testing.T) {
	if got := containerSummaryName(containerSummary{}); got != "" {
		t.Fatalf("name = %q, want empty for nameless summary", got)
	}
}
