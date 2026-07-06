package docker

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/pool/dockerpool"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

func TestPoolEligible(t *testing.T) {
	base := models.CreateSandboxRequest{Image: "alpine:3.20"}
	if !poolEligible(base, nil, 0) {
		t.Fatal("expected eligible base request")
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
		{name: "os_user", req: models.CreateSandboxRequest{Image: "i", OSUser: "root"}},
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

func TestApplyAdoptNetworkPolicy(t *testing.T) {
	c := &Client{networkRules: disabledRules(t)}
	req := models.CreateSandboxRequest{
		NetworkBlockAll: true,
		NetworkAllowOut: []string{"8.8.8.8"},
	}
	if err := c.applyAdoptNetworkPolicy("10.0.0.2", req); err != nil {
		t.Fatalf("apply: %v", err)
	}
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
	create       func() *http.Response
	start        func() *http.Response
	containerGet func() *http.Response
	rename       func() *http.Response
	update       func() *http.Response
	listJSON     func() *http.Response
	removeCalls  int
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
			if d.imageInspect != nil {
				return d.imageInspect(), nil
			}
		case r.Method == http.MethodPost && p == "/containers/create":
			if d.create != nil {
				return d.create(), nil
			}
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/start"):
			if d.start != nil {
				return d.start(), nil
			}
		case r.Method == http.MethodGet && strings.HasPrefix(p, "/containers/") && strings.HasSuffix(p, "/json"):
			if d.containerGet != nil {
				return d.containerGet(), nil
			}
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/rename"):
			if d.rename != nil {
				return d.rename(), nil
			}
			return textResponse(http.StatusNoContent, ""), nil
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/update"):
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
	d.listJSON = func() *http.Response {
		return textResponse(http.StatusOK, `[{"Id":"park-c1"}]`)
	}
	c := newPoolClient(t, d, nil)
	purged, err := c.PurgeParkedContainers(context.Background())
	if err != nil {
		t.Fatalf("purge: %v", err)
	}
	if purged != 1 || d.removeCalls != 1 {
		t.Fatalf("purged=%d removeCalls=%d", purged, d.removeCalls)
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
