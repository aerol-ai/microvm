package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/createtiming"
	"github.com/aerol-ai/microvm/pkg/docker/netrules"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/readyproto"
)

func TestPoolEligible(t *testing.T) {
	base := models.CreateSandboxRequest{Image: "alpine:3.20"}
	if !poolEligible(base, nil, 0) {
		t.Fatal("expected eligible base request")
	}
	// Default create path fills OSUser=root via normalizeCreateRequest; that
	// must remain poolable or every warm-pool create falls through cold.
	if !poolEligible(models.CreateSandboxRequest{Image: "alpine:3.20", OSUser: "root", DiskGB: 10}, nil, 10) {
		t.Fatal("expected root OSUser (normalize default) to be eligible")
	}
	if !poolEligible(models.CreateSandboxRequest{Image: "alpine:3.20", OSUser: "ROOT", DiskGB: 10}, nil, 10) {
		t.Fatal("expected case-insensitive root OSUser to be eligible")
	}
	cases := []struct {
		name string
		req  models.CreateSandboxRequest
		mnts []mounts.ContainerBind
		disk int
	}{
		{name: "env", req: models.CreateSandboxRequest{Image: "i", Env: map[string]string{"K": "V"}}},
		{name: "mounts", req: models.CreateSandboxRequest{Image: "i", Mounts: []models.MountSpec{{Type: "bind", Source: "/a", Target: "/b"}}}},
		{name: "platform_volumes", req: models.CreateSandboxRequest{Image: "i", PlatformVolumes: []models.PlatformVolumeMount{{Name: "v", Path: "/p"}}}},
		{name: "host_mounts", req: models.CreateSandboxRequest{Image: "i"}, mnts: []mounts.ContainerBind{{HostPath: "/h", ContainerPath: "/c"}}},
		{name: "os_user_non_root", req: models.CreateSandboxRequest{Image: "i", OSUser: "ubuntu"}},
		{name: "container_command", req: models.CreateSandboxRequest{Image: "i", ContainerCommand: []string{"sleep"}}},
		{name: "registry", req: models.CreateSandboxRequest{Image: "i", Registry: &models.RegistryAuth{Username: "u"}}},
		{name: "gpus", req: models.CreateSandboxRequest{Image: "i", GPUs: &models.GPURequest{Vendor: models.GPUVendorNVIDIA}}},
		{name: "disk_mismatch", req: models.CreateSandboxRequest{Image: "i", DiskGB: 20}, disk: 10},
		{name: "empty_image", req: models.CreateSandboxRequest{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if poolEligible(tc.req, tc.mnts, tc.disk) {
				t.Fatal("expected ineligible")
			}
		})
	}
}

func TestIsParkedHelpers(t *testing.T) {
	if !isParkedContainerLabels(map[string]string{poolParkLabelKey: poolParkLabelValue}) {
		t.Fatal("expected park label to match")
	}
	if isParkedContainerLabels(map[string]string{managedLabelKey: "true"}) {
		t.Fatal("managed-only labels must not look parked")
	}
	if isParkedContainerLabels(nil) {
		t.Fatal("nil labels must not look parked")
	}
	if !isParkedSandboxID("park-d316b60bc106a6f6") {
		t.Fatal("expected park- prefix id")
	}
	if isParkedSandboxID("sb-abc") {
		t.Fatal("sandbox id must not look parked")
	}
}

func TestIsDockerNameConflict(t *testing.T) {
	if isDockerNameConflict(nil) {
		t.Fatal("nil is not conflict")
	}
	if !isDockerNameConflict(errors.New("name already in use")) {
		t.Fatal("expected conflict")
	}
	if !isDockerNameConflict(errors.New("409 conflict")) {
		t.Fatal("expected 409 conflict")
	}
}

func TestParkDefaultResources(t *testing.T) {
	res := parkDefaultResources(&Client{})
	if res["CpuQuota"] == nil || res["Memory"] == nil {
		t.Fatalf("resources = %#v", res)
	}
}

func TestPoolSpawnerNilSafe(t *testing.T) {
	var nilSpawner *PoolSpawner
	if _, err := nilSpawner.Park(context.Background(), "id", dockerpool.Key{}); err == nil {
		t.Fatal("expected error")
	}
	if err := nilSpawner.DestroyParked(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestSetWarmPool(t *testing.T) {
	c := &Client{}
	pool := dockerpool.New(nil)
	c.SetWarmPool(pool)
	if c.warmPool == nil {
		t.Fatal("expected warm pool wired")
	}
}

// memRuleBackend is an in-memory netrules.RuleBackend that tracks the live
// rule set so tests can assert the terminal iptables state, not just "no
// error". The park DROP and the NetworkBlockAll DROP are the same rule, so
// these tests are the regression guard against an adopt stripping a
// block-all sandbox's isolation.
type memRuleBackend struct {
	rules []string
}

func ruleKey(table, chain string, spec ...string) string {
	return table + "/" + chain + "/" + strings.Join(spec, " ")
}

func (m *memRuleBackend) Exists(table, chain string, spec ...string) (bool, error) {
	return slices.Contains(m.rules, ruleKey(table, chain, spec...)), nil
}

func (m *memRuleBackend) Insert(table, chain string, _ int, spec ...string) error {
	m.rules = append(m.rules, ruleKey(table, chain, spec...))
	return nil
}

func (m *memRuleBackend) Delete(table, chain string, spec ...string) error {
	k := ruleKey(table, chain, spec...)
	for i, r := range m.rules {
		if r == k {
			m.rules = append(m.rules[:i], m.rules[i+1:]...)
			return nil
		}
	}
	return errors.New("No chain/target/match by that name")
}

func (m *memRuleBackend) has(spec ...string) bool {
	ok, _ := m.Exists("filter", "DOCKER-USER", spec...)
	return ok
}

func TestApplyAdoptNetworkPolicy(t *testing.T) {
	const ip = "10.0.0.2"
	parkDrop := []string{"-s", ip, "-j", "DROP"}

	t.Run("block-all request keeps the DROP", func(t *testing.T) {
		backend := &memRuleBackend{}
		rules := netrules.NewWithBackend(backend)
		// Simulate the park-time DROP.
		if err := rules.BlockAllEgress(ip); err != nil {
			t.Fatal(err)
		}
		c := &Client{networkRules: rules}
		req := models.CreateSandboxRequest{NetworkBlockAll: true}
		if err := c.applyAdoptNetworkPolicy(ip, req); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if !backend.has(parkDrop...) {
			t.Fatal("block-all sandbox lost its egress DROP on adopt")
		}
	})

	t.Run("open request clears the park DROP", func(t *testing.T) {
		backend := &memRuleBackend{}
		rules := netrules.NewWithBackend(backend)
		if err := rules.BlockAllEgress(ip); err != nil {
			t.Fatal(err)
		}
		c := &Client{networkRules: rules}
		if err := c.applyAdoptNetworkPolicy(ip, models.CreateSandboxRequest{}); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if backend.has(parkDrop...) {
			t.Fatal("park DROP left behind on an unrestricted sandbox")
		}
	})

	t.Run("allowlist request installs policy then clears park DROP", func(t *testing.T) {
		backend := &memRuleBackend{}
		rules := netrules.NewWithBackend(backend)
		if err := rules.BlockAllEgress(ip); err != nil {
			t.Fatal(err)
		}
		c := &Client{networkRules: rules}
		req := models.CreateSandboxRequest{NetworkAllowOut: []string{"8.8.8.8/32"}}
		if err := c.applyAdoptNetworkPolicy(ip, req); err != nil {
			t.Fatalf("apply: %v", err)
		}
		if backend.has(parkDrop...) {
			t.Fatal("uncommented park DROP should be cleared once the allowlist is in place")
		}
		if !backend.has("-s", ip, "-d", "8.8.8.8/32", "-m", "comment", "--comment", "sbx-egress", "-j", "ACCEPT") {
			t.Fatal("allowlist ACCEPT missing after adopt")
		}
		if !backend.has("-s", ip, "-m", "comment", "--comment", "sbx-egress", "-j", "DROP") {
			t.Fatal("allowlist catch-all DROP missing after adopt")
		}
	})
}

type badParkHandle struct{}

func (badParkHandle) Alive() bool                                         { return true }
func (badParkHandle) Adopt(context.Context, string, string, string) error { return nil }
func (badParkHandle) Close() error                                        { return nil }

func TestAdoptParkedIncompleteSlot(t *testing.T) {
	c := &Client{networkRules: disabledRules(t)}
	if _, err := c.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb", "tok", nil); err == nil {
		t.Fatal("expected incomplete slot error")
	}
	if _, err := c.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb", "tok", &dockerpool.ParkedSlot{
		Handle: badParkHandle{},
	}); err == nil || !strings.Contains(err.Error(), "type mismatch") {
		t.Fatalf("err = %v", err)
	}
}

func TestTryWarmAdoptDisabled(t *testing.T) {
	c := &Client{warmPool: dockerpool.New(nil), readyEnabled: false}
	_, err := c.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{Image: "i"}, "sb", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, dockerpool.ErrNoSlot) {
		t.Fatalf("err = %v", err)
	}
}

func TestTryWarmAdoptIneligible(t *testing.T) {
	c := &Client{
		warmPool:     dockerpool.New(nil),
		readyEnabled: true,
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if strings.HasSuffix(r.URL.Path, "/json") && r.Method == http.MethodGet {
				return jsonResponse(http.StatusOK, map[string]any{"Id": "img-1"}), nil
			}
			return textResponse(http.StatusNotFound, ""), nil
		})},
	}
	req := models.CreateSandboxRequest{Image: "i", Env: map[string]string{"X": "Y"}}
	_, err := c.tryWarmAdopt(context.Background(), req, "sb", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, dockerpool.ErrNoSlot) {
		t.Fatalf("err = %v", err)
	}
}

func TestDestroyParkedNilSafe(t *testing.T) {
	c := &Client{networkRules: disabledRules(t)}
	if err := c.destroyParked(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateContainerResourcesNoop(t *testing.T) {
	c := &Client{resourceLimitsOff: true}
	if err := c.updateContainerResources(context.Background(), "cid", 1, 512); err != nil {
		t.Fatal(err)
	}
}

type poolFakeDaemon struct {
	t            *testing.T
	imageInspect func() *http.Response
	pull         func() *http.Response
	create       func() *http.Response
	start        func() *http.Response
	containerGet func() *http.Response
	rename       func() *http.Response
	update       func() *http.Response
	listJSON     func() *http.Response
	pullCalls    int
	createBodies [][]byte
	updateBodies [][]byte
	removeCalls  int
	// Engine round-trip counters for the warm-adopt fast path: the image-ID
	// cache and slot-carried IP exist to keep these at zero/one per burst.
	imageInspectCalls int
	containerGetCalls int
	imageTagCalls     int
	imageDeleteCalls  int
}

func (d *poolFakeDaemon) transport() roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		p := r.URL.Path
		switch {
		case r.Method == http.MethodGet && p == "/containers/json":
			if d.listJSON != nil {
				return d.listJSON(), nil
			}
			return jsonResponse(http.StatusOK, []containerSummary{}), nil
		case r.Method == http.MethodGet && strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json"):
			d.imageInspectCalls++
			if d.imageInspect != nil {
				return d.imageInspect(), nil
			}
		case r.Method == http.MethodPost && strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/tag"):
			d.imageTagCalls++
			return textResponse(http.StatusCreated, ""), nil
		case r.Method == http.MethodDelete && strings.HasPrefix(p, "/images/"):
			d.imageDeleteCalls++
			return jsonResponse(http.StatusOK, []map[string]string{}), nil
		case r.Method == http.MethodPost && p == "/images/create":
			d.pullCalls++
			if d.pull != nil {
				return d.pull(), nil
			}
			return textResponse(http.StatusOK, "{}"), nil
		case r.Method == http.MethodPost && p == "/containers/create":
			if body, err := io.ReadAll(r.Body); err == nil {
				d.createBodies = append(d.createBodies, body)
			}
			if d.create != nil {
				return d.create(), nil
			}
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/start"):
			if d.start != nil {
				return d.start(), nil
			}
		case r.Method == http.MethodGet && strings.HasPrefix(p, "/containers/") && strings.HasSuffix(p, "/json"):
			d.containerGetCalls++
			if d.containerGet != nil {
				return d.containerGet(), nil
			}
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/rename"):
			if d.rename != nil {
				return d.rename(), nil
			}
			return textResponse(http.StatusNoContent, ""), nil
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/update"):
			if body, err := io.ReadAll(r.Body); err == nil {
				d.updateBodies = append(d.updateBodies, body)
			}
			if d.update != nil {
				return d.update(), nil
			}
			return textResponse(http.StatusOK, ""), nil
		case r.Method == http.MethodDelete && strings.HasPrefix(p, "/containers/"):
			d.removeCalls++
			return textResponse(http.StatusNoContent, ""), nil
		}
		return textResponse(http.StatusNotFound, "no such endpoint: "+r.Method+" "+p), nil
	}
}

func newPoolClient(t *testing.T, d *poolFakeDaemon, mutate func(*Client)) *Client {
	t.Helper()
	if d.imageInspect == nil {
		d.imageInspect = func() *http.Response {
			return jsonResponse(http.StatusOK, map[string]any{
				"Id": "sha256:img1",
				"Config": map[string]any{
					"WorkingDir": "/",
					"Entrypoint": []string{},
					"Cmd":        []string{"/bin/sh"},
				},
			})
		}
	}
	if d.create == nil {
		d.create = func() *http.Response {
			return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid-park"})
		}
	}
	if d.start == nil {
		d.start = func() *http.Response { return textResponse(http.StatusNoContent, "") }
	}
	if d.containerGet == nil {
		d.containerGet = func() *http.Response {
			return textResponse(http.StatusOK, inspectBody("cid-park", "/park-1", "172.17.0.9", true, "running", 42))
		}
	}
	c := &Client{
		logger:             slogDefault(),
		toolboxBinaryPath:  writableToolbox(t),
		toolboxMountPath:   "/usr/local/bin/toolboxd",
		toolboxPort:        2280,
		networkRules:       disabledRules(t),
		httpClient:         &http.Client{Transport: d.transport()},
		streamClient:       &http.Client{Transport: d.transport()},
		toolboxWaitTimeout: 2 * time.Second,
		readyEnabled:       true,
		readyDir:           t.TempDir(),
		defaultRuntime:     models.RuntimeDocker,
	}
	if mutate != nil {
		mutate(c)
	}
	return c
}

func slogDefault() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestListAndPurgeParkedContainers(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	var listQuery url.Values
	d.listJSON = func() *http.Response {
		return textResponse(http.StatusOK, `[{"Id":"park-c1"}]`)
	}
	c := newPoolClient(t, d, func(c *Client) {
		inner := c.httpClient.Transport
		c.httpClient.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/containers/json" {
				listQuery = r.URL.Query()
			}
			return inner.RoundTrip(r)
		})
	})
	purged, err := c.PurgeParkedContainers(context.Background())
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged != 1 || d.removeCalls != 1 {
		t.Fatalf("purged=%d removeCalls=%d", purged, d.removeCalls)
	}
	// all=1 or exited/crashed parked containers (and their DROP rules)
	// survive every boot purge.
	if got := listQuery.Get("all"); got != "1" {
		t.Fatalf("purge list all=%q, want 1", got)
	}
}

func TestPurgeParkedContainersListError(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	d.listJSON = func() *http.Response { return textResponse(http.StatusInternalServerError, "boom") }
	c := newPoolClient(t, d, nil)
	if _, err := c.PurgeParkedContainers(context.Background()); err == nil {
		t.Fatal("expected list error")
	}
}

// TestTryWarmAdoptFailureReleasesReservation guards the adopt-failure leak:
// once a slot leaves the pool via Acquire, only tryWarmAdopt can free its
// park:<slot-id> capacity reservation. Without the release every failed adopt
// permanently shrinks the node's admittable capacity.
func TestTryWarmAdoptFailureReleasesReservation(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	c := newPoolClient(t, d, nil)
	pool := dockerpool.New(slogDefault())
	var released []string
	pool.SetParkReleaser(func(slotID string) { released = append(released, slotID) })
	c.SetWarmPool(pool)

	key := dockerpool.KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)
	// badParkHandle fails adoptParked's handle type assertion — an adopt
	// failure after the slot has already left the pool.
	pool.RecordLoaded(&dockerpool.ParkedSlot{
		ID:          "park-fail",
		ContainerID: "cid-park",
		ImageID:     "sha256:img1",
		Key:         key,
		Handle:      badParkHandle{},
	})

	ctx, timing := createtiming.With(context.Background())
	_, err := c.tryWarmAdopt(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-1", "tok", nil, models.RuntimeDocker)
	if err == nil || errors.Is(err, dockerpool.ErrNoSlot) {
		t.Fatalf("expected adopt failure, got %v", err)
	}
	if len(released) != 1 || released[0] != "park-fail" {
		t.Fatalf("park reservation not released on adopt failure: %v", released)
	}
	if d.removeCalls != 1 {
		t.Fatalf("parked container not destroyed: removeCalls=%d", d.removeCalls)
	}
	// A burned slot must not masquerade as an ordinary miss in Server-Timing
	// — that disguise is how a 100% adopt-failure rate hid in bench data.
	var poolStage *createtiming.Stage
	for _, st := range timing.Stages() {
		if st.Name == "docker_pool" {
			poolStage = &st
			break
		}
	}
	if poolStage == nil || poolStage.Desc != "adopt_failed" {
		t.Fatalf("docker_pool stage = %+v, want desc=adopt_failed", poolStage)
	}
}

// TestTryWarmAdoptRenameConflictReturnsSlot: a duplicate-create rename
// conflict happens before the slot is touched, so the parked container goes
// back to the pool — not destroyed, reservation kept.
func TestTryWarmAdoptRenameConflictReturnsSlot(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	d.rename = func() *http.Response {
		return textResponse(http.StatusConflict, `name "/sb-dup" is already in use`)
	}
	c := newPoolClient(t, d, nil)
	pool := dockerpool.New(slogDefault())
	var released []string
	pool.SetParkReleaser(func(slotID string) { released = append(released, slotID) })
	c.SetWarmPool(pool)

	pl, err := NewParkedListener(shortParkTestDir(t), "park-dup", "tok", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })

	// Acquire only hands out slots with a live held connection, so park a
	// real guest on the socket and keep it open for the duration.
	closeGuest := make(chan struct{})
	t.Cleanup(func() { close(closeGuest) })
	go func() {
		conn, err := net.Dial("unix", pl.HostSocketPath())
		if err != nil {
			return
		}
		defer conn.Close()
		_ = readyproto.EncodeParked(conn, readyproto.ParkedSignal{
			Event: readyproto.EventParked, Token: "tok", Nonce: "nonce",
		})
		<-closeGuest
	}()
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pl.WaitParked(waitCtx); err != nil {
		t.Fatalf("WaitParked: %v", err)
	}

	key := dockerpool.KeyFromRequest(models.CreateSandboxRequest{Image: "alpine:3.20"}, models.RuntimeDocker)
	pool.RecordLoaded(&dockerpool.ParkedSlot{
		ID:          "park-dup",
		ContainerID: "cid-park",
		ImageID:     "sha256:img1",
		Key:         key,
		Handle:      pl,
	})

	_, err = c.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb-dup", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, ErrSandboxContainerExists) {
		t.Fatalf("err = %v", err)
	}
	if len(released) != 0 {
		t.Fatalf("pristine slot's reservation must not be released: %v", released)
	}
	if d.removeCalls != 0 {
		t.Fatalf("pristine slot must not be destroyed: removeCalls=%d", d.removeCalls)
	}
}

func TestTryWarmAdoptInspectFailure(t *testing.T) {
	c := &Client{
		warmPool:     dockerpool.New(nil),
		readyEnabled: true,
		httpClient: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			return textResponse(http.StatusNotFound, "no image"), nil
		})},
	}
	_, err := c.tryWarmAdopt(context.Background(), models.CreateSandboxRequest{Image: "missing"}, "sb", "tok", nil, models.RuntimeDocker)
	if !errors.Is(err, dockerpool.ErrNoSlot) {
		t.Fatalf("err = %v", err)
	}
}

func TestUpdateContainerResourcesAppliesLimits(t *testing.T) {
	var updated bool
	d := &poolFakeDaemon{t: t}
	d.update = func() *http.Response {
		updated = true
		return textResponse(http.StatusOK, "")
	}
	c := newPoolClient(t, d, nil)
	if err := c.updateContainerResources(context.Background(), "cid", 2, 1024); err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Fatal("expected update call")
	}
}

func TestDestroyParkedClearsRulesAndContainer(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	c := newPoolClient(t, d, nil)
	dir, _ := os.MkdirTemp("", "rd")
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	pl, err := NewParkedListener(dir, "park-d", "tok", "n")
	if err != nil {
		t.Fatal(err)
	}
	slot := &dockerpool.ParkedSlot{
		ContainerID: "cid-d",
		ContainerIP: "10.0.0.5",
		Handle:      pl,
	}
	if err := c.destroyParked(context.Background(), slot); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if d.removeCalls != 1 {
		t.Fatalf("remove calls = %d", d.removeCalls)
	}
}

func TestApplyAdoptNetworkPolicyEgressLists(t *testing.T) {
	c := &Client{networkRules: disabledRules(t)}
	req := models.CreateSandboxRequest{
		NetworkAllowOut: []string{"10.0.0.1"},
		NetworkDenyOut:  []string{"10.0.0.2"},
	}
	if err := c.applyAdoptNetworkPolicy("172.17.0.2", req); err != nil {
		t.Fatal(err)
	}
}

func TestPoolSpawnerParkNotConfigured(t *testing.T) {
	sp := &PoolSpawner{}
	if _, err := sp.Park(context.Background(), "id", dockerpool.Key{}); err == nil {
		t.Fatal("expected error")
	}
}

func TestRenameContainerConflictMapsToExists(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	dir, err := os.MkdirTemp("", "rd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	c := newPoolClient(t, d, func(c *Client) { c.readyDir = dir })
	d.rename = func() *http.Response {
		return textResponse(http.StatusConflict, "name already in use")
	}
	pl, err := NewParkedListener(c.readyDir, "park-x", "boot", "nonce-park")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })

	slot := &dockerpool.ParkedSlot{
		ID:          "park-x",
		ContainerID: "cid-park",
		ContainerIP: "10.0.0.2",
		Handle:      pl,
	}
	_, err = c.adoptParked(context.Background(), models.CreateSandboxRequest{}, "sb-dup", "tok", slot)
	if !errors.Is(err, ErrSandboxContainerExists) {
		t.Fatalf("err = %v", err)
	}
}

// A fresh host has no images: parkContainer must self-warm with a pull
// instead of failing every refill tick until some sandbox create happens to
// pull the image (pinned targets would otherwise never pre-warm at all).
// The park-default resource limits must also land INLINE in HostConfig —
// dockerd silently drops an unknown nested "Resources" key.
func TestParkContainerPullsMissingImageAndInlinesLimits(t *testing.T) {
	pulled := false
	d := &poolFakeDaemon{t: t}
	d.imageInspect = func() *http.Response {
		if !pulled {
			return textResponse(http.StatusNotFound, `{"message":"No such image"}`)
		}
		return jsonResponse(http.StatusOK, map[string]any{
			"Id":     "sha256:img1",
			"Config": map[string]any{"WorkingDir": "/", "Cmd": []string{"/bin/sh"}},
		})
	}
	d.pull = func() *http.Response {
		pulled = true
		return textResponse(http.StatusOK, "{}")
	}
	// Fail the container create: it proves the flow got past pull+re-inspect
	// without needing a live parked-handshake guest.
	d.create = func() *http.Response {
		return textResponse(http.StatusInternalServerError, `{"message":"boom"}`)
	}
	dir, err := os.MkdirTemp("", "rd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	c := newPoolClient(t, d, func(c *Client) {
		c.pulls = make(map[string]*imagePull)
		c.readyDir = dir
	})

	_, err = c.parkContainer(context.Background(), "park-test1", dockerpool.Key{
		Image: "alpine:3.20", Runtime: models.RuntimeDocker,
	})
	if err == nil || !strings.Contains(err.Error(), "park create") {
		t.Fatalf("err = %v, want park create failure after successful pull", err)
	}
	if d.pullCalls != 1 {
		t.Fatalf("pull calls = %d, want 1", d.pullCalls)
	}
	if len(d.createBodies) != 1 {
		t.Fatalf("create bodies = %d", len(d.createBodies))
	}
	var body struct {
		HostConfig map[string]any `json:"HostConfig"`
	}
	if err := json.Unmarshal(d.createBodies[0], &body); err != nil {
		t.Fatalf("create body: %v", err)
	}
	if _, nested := body.HostConfig["Resources"]; nested {
		t.Fatal(`park create body nests limits under "Resources" — dockerd drops that key`)
	}
	if body.HostConfig["Memory"] == nil || body.HostConfig["CpuQuota"] == nil {
		t.Fatalf("park create body missing inline Memory/CpuQuota: %v", body.HostConfig)
	}
}

// Content-addressed local build tags cannot exist on a registry — a missing
// one must fail immediately (feeding target eviction) without a pull attempt.
func TestParkContainerLocalOnlyImageSkipsPull(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	d.imageInspect = func() *http.Response {
		return textResponse(http.StatusNotFound, `{"message":"No such image"}`)
	}
	dir, err := os.MkdirTemp("", "rd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	c := newPoolClient(t, d, func(c *Client) {
		c.pulls = make(map[string]*imagePull)
		c.readyDir = dir
	})

	_, err = c.parkContainer(context.Background(), "park-test2", dockerpool.Key{
		Image: BuiltImageNamespace + "/deadbeef:latest", Runtime: models.RuntimeDocker,
	})
	if err == nil || !strings.Contains(err.Error(), "inspect image") {
		t.Fatalf("err = %v, want inspect failure", err)
	}
	if d.pullCalls != 0 {
		t.Fatalf("pull calls = %d, want 0 for local-only ref", d.pullCalls)
	}
}

// /containers/{id}/update takes container.UpdateConfig, which embeds the
// Resources fields inline — nesting them under "Resources" is silently
// ignored and an adopted container would keep its park-default limits.
func TestUpdateContainerResourcesInlineBody(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	c := newPoolClient(t, d, nil)

	if err := c.updateContainerResources(context.Background(), "cid1", 2, 1024); err != nil {
		t.Fatal(err)
	}
	if len(d.updateBodies) != 1 {
		t.Fatalf("update bodies = %d", len(d.updateBodies))
	}
	var body map[string]any
	if err := json.Unmarshal(d.updateBodies[0], &body); err != nil {
		t.Fatalf("update body: %v", err)
	}
	if _, nested := body["Resources"]; nested {
		t.Fatal(`update body nests limits under "Resources" — dockerd ignores that key`)
	}
	if body["Memory"] == nil || body["CpuQuota"] == nil {
		t.Fatalf("update body missing inline Memory/CpuQuota: %v", body)
	}
}

// The cold fallback is the safety net under every warm-pool defect: when an
// adopt burns its slot, Create must still deliver a working sandbox AND the
// Server-Timing must tell the truth about what happened — an adopt_failed
// stage followed by the cold docker_create stage, not a disguised miss.
func TestCreate_WarmAdoptFailureFallsBackToColdCreate(t *testing.T) {
	d := &fakeDaemon{
		t: t,
		imageInspect: func() *http.Response {
			return jsonResponse(http.StatusOK, map[string]any{
				"Id":     "sha256:img1",
				"Config": map[string]any{"WorkingDir": "/", "Entrypoint": []string{}, "Cmd": []string{"/bin/sh"}},
			})
		},
		create: func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid-cold"}) },
		start:  func() *http.Response { return textResponse(http.StatusNoContent, "") },
	}
	readyDir, err := os.MkdirTemp("", "rd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(readyDir) })

	pool := dockerpool.New(slogDefault())
	var released []string
	pool.SetParkReleaser(func(slotID string) { released = append(released, slotID) })
	c := newCreateClient(t, d, true, func(c *Client) {
		c.defaultRuntime = models.RuntimeDocker
		c.readyEnabled = true
		c.readyDir = readyDir
		c.SetWarmPool(pool)
	})

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	key := dockerpool.KeyFromRequest(req, models.RuntimeDocker)
	// badParkHandle fails adoptParked before any engine call; ImageID must
	// match the inspect response or Acquire discards the slot as stale and
	// the create records a plain miss instead of an adopt failure.
	pool.RecordLoaded(&dockerpool.ParkedSlot{
		ID:          "park-burn",
		ContainerID: "cid-park",
		ImageID:     "sha256:img1",
		Key:         key,
		Handle:      badParkHandle{},
	})

	ctx, timing := createtiming.With(context.Background())
	rt, err := c.Create(ctx, req, "sb", "tok", nil)
	if err != nil {
		t.Fatalf("Create() = %v, want cold fallback success", err)
	}
	// AdoptedParkID empty proves the runtime came from the cold path, not
	// the burned slot (the inspect stub reports its own container id).
	if rt.AdoptedParkID != "" || rt.Status != models.SandboxStatusStarted {
		t.Fatalf("runtime = %+v, want cold-created container", rt)
	}
	if len(released) != 1 || released[0] != "park-burn" {
		t.Fatalf("burned slot reservation not released: %v", released)
	}
	if d.removeCalls != 1 {
		t.Fatalf("burned park container not destroyed: removeCalls=%d", d.removeCalls)
	}
	stages := map[string]string{}
	for _, st := range timing.Stages() {
		stages[st.Name] = st.Desc
	}
	if stages["docker_pool"] != "adopt_failed" {
		t.Fatalf("docker_pool desc = %q, want adopt_failed (stages=%v)", stages["docker_pool"], stages)
	}
	if _, cold := stages["docker_create"]; !cold {
		t.Fatalf("cold docker_create stage missing after adopt failure (stages=%v)", stages)
	}
}

// A pool miss must run the cold path untouched AND register the miss-driven
// self-warm target under the same canonical keystring a boot-time pin would
// use — that collision is what makes the next create a warm hit.
func TestCreate_PoolMissRunsColdAndRegistersTarget(t *testing.T) {
	d := &fakeDaemon{
		t: t,
		imageInspect: func() *http.Response {
			return jsonResponse(http.StatusOK, map[string]any{
				"Id":     "sha256:img1",
				"Config": map[string]any{"WorkingDir": "/", "Entrypoint": []string{}, "Cmd": []string{"/bin/sh"}},
			})
		},
		create: func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid-cold"}) },
		start:  func() *http.Response { return textResponse(http.StatusNoContent, "") },
	}
	readyDir, err := os.MkdirTemp("", "rd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(readyDir) })

	pool := dockerpool.New(slogDefault())
	c := newCreateClient(t, d, true, func(c *Client) {
		c.defaultRuntime = models.RuntimeDocker
		c.readyEnabled = true
		c.readyDir = readyDir
		c.SetWarmPool(pool)
	})

	ctx, timing := createtiming.With(context.Background())
	rt, err := c.Create(ctx, models.CreateSandboxRequest{Image: "alpine:3.20"}, "sb", "tok", nil)
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	if rt.AdoptedParkID != "" || rt.Status != models.SandboxStatusStarted {
		t.Fatalf("runtime = %+v, want cold-created container", rt)
	}
	stages := map[string]string{}
	for _, st := range timing.Stages() {
		stages[st.Name] = st.Desc
	}
	if stages["docker_pool"] != "miss" {
		t.Fatalf("docker_pool desc = %q, want miss (stages=%v)", stages["docker_pool"], stages)
	}
	if _, cold := stages["docker_create"]; !cold {
		t.Fatalf("cold docker_create stage missing on miss (stages=%v)", stages)
	}
	targets := pool.ListTargets()
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want 1 miss-driven target", len(targets))
	}
	pinned := dockerpool.Key{Image: "alpine:3.20", Runtime: models.RuntimeDocker}
	if targets[0].KeyString() != pinned.KeyString() {
		t.Fatalf("miss target key %q does not collide with pin key %q", targets[0].KeyString(), pinned.KeyString())
	}
}

// A duplicate-create rename conflict must surface ErrSandboxContainerExists
// from Create itself — NOT fall through to a cold create, which would race
// the concurrent duplicate for the same container name (pr-review §1).
func TestCreate_RenameConflictSkipsColdFallback(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	d.rename = func() *http.Response {
		return textResponse(http.StatusConflict, `name "/sb-dup" is already in use`)
	}
	c := newPoolClient(t, d, nil)
	pool := dockerpool.New(slogDefault())
	c.SetWarmPool(pool)

	pl, err := NewParkedListener(shortParkTestDir(t), "park-dup2", "tok", "nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })
	closeGuest := make(chan struct{})
	t.Cleanup(func() { close(closeGuest) })
	go func() {
		conn, err := net.Dial("unix", pl.HostSocketPath())
		if err != nil {
			return
		}
		defer conn.Close()
		_ = readyproto.EncodeParked(conn, readyproto.ParkedSignal{
			Event: readyproto.EventParked, Token: "tok", Nonce: "nonce",
		})
		<-closeGuest
	}()
	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pl.WaitParked(waitCtx); err != nil {
		t.Fatalf("WaitParked: %v", err)
	}

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	key := dockerpool.KeyFromRequest(req, models.RuntimeDocker)
	pool.RecordLoaded(&dockerpool.ParkedSlot{
		ID:          "park-dup2",
		ContainerID: "cid-park",
		ImageID:     "sha256:img1",
		Key:         key,
		Handle:      pl,
	})

	_, err = c.Create(context.Background(), req, "sb-dup", "tok", nil)
	if !errors.Is(err, ErrSandboxContainerExists) {
		t.Fatalf("Create() = %v, want ErrSandboxContainerExists", err)
	}
	if len(d.createBodies) != 0 {
		t.Fatalf("cold create attempted despite duplicate-name conflict: %d bodies", len(d.createBodies))
	}
	if d.removeCalls != 0 {
		t.Fatalf("pristine slot destroyed on rename conflict: removeCalls=%d", d.removeCalls)
	}
	if !pool.HasReady(key) {
		t.Fatal("slot not returned to the pool after rename conflict")
	}
}

// parkGuestSlot parks one slot into the pool backed by a real ParkedListener
// with a guest goroutine that completes the adopt handshake (parked signal →
// adopt frame → ready ack), mirroring toolboxd's park-mode behavior.
func parkGuestSlot(t *testing.T, pool *dockerpool.Pool, key dockerpool.Key, slotID, containerID, containerIP string) {
	t.Helper()
	pl, err := NewParkedListener(shortParkTestDir(t), slotID, "boot-tok", "boot-nonce")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pl.Close() })

	go func() {
		conn, err := net.Dial("unix", pl.HostSocketPath())
		if err != nil {
			return
		}
		defer conn.Close()
		if err := readyproto.EncodeParked(conn, readyproto.ParkedSignal{
			Event: readyproto.EventParked, Token: "boot-tok", Nonce: "boot-nonce",
		}); err != nil {
			return
		}
		frame, err := readyproto.DecodeAdopt(bufio.NewReader(conn))
		if err != nil {
			return
		}
		_ = readyproto.Encode(conn, readyproto.ReadySignal{
			Event:     readyproto.EventReady,
			SandboxID: frame.SandboxID,
			Token:     frame.Token,
			Nonce:     frame.Nonce,
		})
	}()

	waitCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := pl.WaitParked(waitCtx); err != nil {
		t.Fatalf("WaitParked(%s): %v", slotID, err)
	}
	pool.RecordLoaded(&dockerpool.ParkedSlot{
		ID:          slotID,
		ContainerID: containerID,
		ContainerIP: containerIP,
		ImageID:     "sha256:img1",
		Key:         key,
		Handle:      pl,
	})
}

// The warm-hit fast path: consecutive default-shaped adopts must pay exactly
// one image-inspect round-trip (second create hits the image-ID cache), zero
// container update calls (park shape == normalized default shape), and zero
// post-adopt container inspects (the slot carries its park-time IP).
func TestCreate_WarmAdoptFastPathSkipsEngineRoundTrips(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	pool := dockerpool.New(slogDefault())
	c := newPoolClient(t, d, func(c *Client) {
		c.SetWarmPool(pool)
		c.imageIDs = newImageIDCache(time.Minute)
	})

	req := models.CreateSandboxRequest{
		Image:    "alpine:3.20",
		CPU:      models.DefaultCPU,
		MemoryMB: models.DefaultMemoryMB,
	}
	key := dockerpool.KeyFromRequest(req, models.RuntimeDocker)
	parkGuestSlot(t, pool, key, "park-fp1", "cid-park-1", "172.17.0.9")
	parkGuestSlot(t, pool, key, "park-fp2", "cid-park-2", "172.17.0.10")

	ctx1, timing1 := createtiming.With(context.Background())
	rt1, err := c.Create(ctx1, req, "sb-fp1", "tok", nil)
	if err != nil {
		t.Fatalf("first Create() = %v", err)
	}
	ctx2, timing2 := createtiming.With(context.Background())
	rt2, err := c.Create(ctx2, req, "sb-fp2", "tok", nil)
	if err != nil {
		t.Fatalf("second Create() = %v", err)
	}

	if rt1.AdoptedParkID == "" || rt2.AdoptedParkID == "" {
		t.Fatalf("expected both creates to adopt, got %q / %q", rt1.AdoptedParkID, rt2.AdoptedParkID)
	}
	if rt1.ContainerIP == "" || rt2.ContainerIP == "" {
		t.Fatalf("adopted runtimes missing slot-carried IPs: %q / %q", rt1.ContainerIP, rt2.ContainerIP)
	}
	if d.imageInspectCalls != 1 {
		t.Fatalf("image inspects = %d, want 1 (second adopt must hit the image-ID cache)", d.imageInspectCalls)
	}
	if len(d.updateBodies) != 0 {
		t.Fatalf("update calls = %d, want 0 (default shape matches park shape)", len(d.updateBodies))
	}
	if d.containerGetCalls != 0 {
		t.Fatalf("container inspects = %d, want 0 (slot carries the park-time IP)", d.containerGetCalls)
	}

	stagesOf := func(tm *createtiming.CreateTiming) map[string]string {
		out := map[string]string{}
		for _, st := range tm.Stages() {
			out[st.Name] = st.Desc
		}
		return out
	}
	first, second := stagesOf(timing1), stagesOf(timing2)
	if first["docker_pool"] != "hit" || second["docker_pool"] != "hit" {
		t.Fatalf("docker_pool descs = %q / %q, want hit/hit", first["docker_pool"], second["docker_pool"])
	}
	if first["docker_image"] != "resolve" {
		t.Fatalf("first create docker_image desc = %q, want resolve (cache miss pays the inspect)", first["docker_image"])
	}
	if _, ok := second["docker_image"]; ok {
		t.Fatalf("second create recorded docker_image %q; cache hit must skip the inspect stage", second["docker_image"])
	}
}

// A request that diverges from the park shape must still resize the adopted
// container — the skip is strictly for the byte-identical default shape.
func TestCreate_WarmAdoptCustomShapeStillUpdates(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	pool := dockerpool.New(slogDefault())
	c := newPoolClient(t, d, func(c *Client) {
		c.SetWarmPool(pool)
		c.imageIDs = newImageIDCache(time.Minute)
	})

	req := models.CreateSandboxRequest{Image: "alpine:3.20", CPU: 2, MemoryMB: 2048}
	key := dockerpool.KeyFromRequest(req, models.RuntimeDocker)
	parkGuestSlot(t, pool, key, "park-cs1", "cid-park-1", "172.17.0.9")

	rt, err := c.Create(context.Background(), req, "sb-cs1", "tok", nil)
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	if rt.AdoptedParkID == "" {
		t.Fatal("expected a warm adopt")
	}
	if len(d.updateBodies) != 1 {
		t.Fatalf("update calls = %d, want 1 for a non-default shape", len(d.updateBodies))
	}
	var body map[string]any
	if err := json.Unmarshal(d.updateBodies[0], &body); err != nil {
		t.Fatalf("update body: %v", err)
	}
	if body["CpuQuota"] != float64(200000) {
		t.Fatalf("CpuQuota = %v, want 200000", body["CpuQuota"])
	}
	if body["Memory"] != float64(2048*1024*1024) {
		t.Fatalf("Memory = %v, want 2GiB", body["Memory"])
	}
}

// sandboxd-driven image mutations must flush the resolution cache so the
// next warm probe re-inspects instead of adopting against a pre-change ID.
func TestImageMutationsFlushImageIDCache(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	c := newPoolClient(t, d, func(c *Client) {
		c.imageIDs = newImageIDCache(time.Minute)
		c.pulls = make(map[string]*imagePull)
		c.pullFailures = make(map[string]imagePullFailure)
	})

	seed := func() {
		c.imageIDs.Put("alpine:3.20", "sha256:old")
		if _, ok := c.imageIDs.Get("alpine:3.20"); !ok {
			t.Fatal("seed entry missing")
		}
	}

	seed()
	if err := c.PullImage(context.Background(), "alpine:3.20", nil); err != nil {
		t.Fatalf("PullImage: %v", err)
	}
	if _, ok := c.imageIDs.Get("alpine:3.20"); ok {
		t.Fatal("pull must flush the cached resolution")
	}

	seed()
	if err := c.RemoveImage(context.Background(), "alpine:3.20"); err != nil {
		t.Fatalf("RemoveImage: %v", err)
	}
	if _, ok := c.imageIDs.Get("alpine:3.20"); ok {
		t.Fatal("image delete must flush the cached resolution")
	}
	if d.imageDeleteCalls != 1 {
		t.Fatalf("imageDeleteCalls = %d, want 1", d.imageDeleteCalls)
	}

	seed()
	if err := c.tagImage(context.Background(), "sha256:new", "alpine", "3.20"); err != nil {
		t.Fatalf("tagImage: %v", err)
	}
	if _, ok := c.imageIDs.Get("alpine:3.20"); ok {
		t.Fatal("tag must flush the cached resolution for the target ref")
	}
	if d.imageTagCalls != 1 {
		t.Fatalf("imageTagCalls = %d, want 1", d.imageTagCalls)
	}
}

// A slot that somehow parked without an IP must fall back to the container
// inspect instead of returning an empty ContainerIP to the service layer.
func TestCreate_WarmAdoptEmptySlotIPFallsBackToInspect(t *testing.T) {
	d := &poolFakeDaemon{t: t}
	pool := dockerpool.New(slogDefault())
	c := newPoolClient(t, d, func(c *Client) {
		c.SetWarmPool(pool)
		c.imageIDs = newImageIDCache(time.Minute)
	})

	req := models.CreateSandboxRequest{Image: "alpine:3.20"}
	key := dockerpool.KeyFromRequest(req, models.RuntimeDocker)
	parkGuestSlot(t, pool, key, "park-noip", "cid-park", "")

	rt, err := c.Create(context.Background(), req, "sb-noip", "tok", nil)
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	if d.containerGetCalls != 1 {
		t.Fatalf("container inspects = %d, want exactly the fallback one", d.containerGetCalls)
	}
	if rt.ContainerIP != "172.17.0.9" {
		t.Fatalf("ContainerIP = %q, want the inspect-provided 172.17.0.9", rt.ContainerIP)
	}
}
