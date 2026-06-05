package docker

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// fakeDaemon is a configurable Docker-API stub. Each field, when set, handles
// the matching endpoint; unset endpoints fall through to a 404 so a test only
// wires the routes its path exercises.
type fakeDaemon struct {
	t            *testing.T
	imageInspect func() *http.Response // GET /images/{ref}/json
	pull         func() *http.Response // POST /images/create
	create       func() *http.Response // POST /containers/create
	start        func() *http.Response // POST /containers/{id}/start
	containerGet func() *http.Response // GET /containers/{id}/json (waitForRuntime / inspect)
	remove       func() *http.Response // DELETE /containers/{id}
	removeCalls  int
}

func (d *fakeDaemon) transport() roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		p := r.URL.Path
		switch {
		case r.Method == http.MethodGet && strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json"):
			if d.imageInspect != nil {
				return d.imageInspect(), nil
			}
		case r.Method == http.MethodPost && p == "/images/create":
			if d.pull != nil {
				return d.pull(), nil
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
		case r.Method == http.MethodDelete && strings.HasPrefix(p, "/containers/"):
			d.removeCalls++
			if d.remove != nil {
				return d.remove(), nil
			}
			return textResponse(http.StatusNoContent, ""), nil
		}
		return textResponse(http.StatusNotFound, "no such endpoint: "+r.Method+" "+p), nil
	}
}

// newCreateClient wires a Client around a fake daemon + a real toolbox health
// server so the waitForRuntime → waitForToolbox handshake completes.
func newCreateClient(t *testing.T, d *fakeDaemon, toolboxOK bool, mutate func(*Client)) *Client {
	t.Helper()
	ip, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) {
		if toolboxOK {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	})
	t.Cleanup(closeFn)

	// Default container inspect returns the loopback IP so waitForToolbox dials
	// the real httptest server above.
	if d.containerGet == nil {
		d.containerGet = func() *http.Response {
			return textResponse(http.StatusOK, inspectBody("cid", "/sb", ip, true, "running", 7))
		}
	}

	c := &Client{
		logger:             slog.Default(),
		toolboxBinaryPath:  writableToolbox(t),
		toolboxMountPath:   "/usr/local/bin/toolboxd",
		toolboxPort:        port,
		networkRules:       disabledRules(t),
		httpClient:         &http.Client{Transport: d.transport()},
		streamClient:       &http.Client{Transport: d.transport()},
		toolboxClient:      &http.Client{Timeout: 2 * time.Second},
		waitTimeout:        2 * time.Second,
		toolboxWaitTimeout: 2 * time.Second,
		pulls:              map[string]*imagePull{},
		pullFailures:       map[string]imagePullFailure{},
	}
	if mutate != nil {
		mutate(c)
	}
	return c
}

func writableToolbox(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "toolboxd")
	if err := os.WriteFile(path, []byte("binary"), 0o755); err != nil {
		t.Fatalf("write toolbox: %v", err)
	}
	return path
}

func TestCreate_Validation(t *testing.T) {
	t.Run("empty_sandbox_id", func(t *testing.T) {
		c := &Client{}
		if _, err := c.Create(context.Background(), models.CreateSandboxRequest{}, "  ", "tok", nil); err == nil {
			t.Fatal("Create() expected empty sandbox ID error")
		}
	})

	t.Run("toolbox_binary_missing", func(t *testing.T) {
		c := &Client{toolboxBinaryPath: "/nonexistent/toolboxd-xyz"}
		if _, err := c.Create(context.Background(), models.CreateSandboxRequest{}, "sb", "tok", nil); err == nil {
			t.Fatal("Create() expected toolbox-binary error")
		}
	})

	t.Run("gvisor_privileged_conflict", func(t *testing.T) {
		c := newCreateClient(t, &fakeDaemon{t: t}, true, func(c *Client) { c.privileged = true })
		req := models.CreateSandboxRequest{Image: "img", Runtime: models.RuntimeGvisor}
		if _, err := c.Create(context.Background(), req, "sb", "tok", nil); err == nil ||
			!strings.Contains(err.Error(), "incompatible with privileged") {
			t.Fatalf("Create() gvisor+privileged err = %v", err)
		}
	})

	t.Run("gvisor_gpu_conflict", func(t *testing.T) {
		c := newCreateClient(t, &fakeDaemon{t: t}, true, nil)
		req := models.CreateSandboxRequest{
			Image:   "img",
			Runtime: models.RuntimeGvisor,
			GPUs:    &models.GPURequest{Vendor: models.GPUVendorNVIDIA},
		}
		if _, err := c.Create(context.Background(), req, "sb", "tok", nil); err == nil ||
			!strings.Contains(err.Error(), "GPU access is not supported") {
			t.Fatalf("Create() gvisor+gpu err = %v", err)
		}
	})

	t.Run("kata_runtime_rejected", func(t *testing.T) {
		c := newCreateClient(t, &fakeDaemon{t: t}, true, nil)
		req := models.CreateSandboxRequest{Image: "img", Runtime: models.RuntimeKata}
		if _, err := c.Create(context.Background(), req, "sb", "tok", nil); err == nil {
			t.Fatal("Create() expected kata runtime rejection")
		}
	})

	t.Run("local_only_image_missing", func(t *testing.T) {
		d := &fakeDaemon{t: t, imageInspect: func() *http.Response { return textResponse(http.StatusNotFound, "no such image") }}
		c := newCreateClient(t, d, true, nil)
		req := models.CreateSandboxRequest{Image: BuiltImageNamespace + "/abc:latest"}
		if _, err := c.Create(context.Background(), req, "sb", "tok", nil); err == nil ||
			!strings.Contains(err.Error(), "local-only") {
			t.Fatalf("Create() local-only err = %v", err)
		}
	})

	t.Run("local_only_distribution_mode_missing", func(t *testing.T) {
		d := &fakeDaemon{t: t, imageInspect: func() *http.Response { return textResponse(http.StatusNotFound, "no such image") }}
		c := newCreateClient(t, d, true, nil)
		req := models.CreateSandboxRequest{Image: "registry.example/app:v1", ImageDistributionMode: models.ImageDistributionLocalOnly}
		if _, err := c.Create(context.Background(), req, "sb", "tok", nil); err == nil ||
			!strings.Contains(err.Error(), "local-only") {
			t.Fatalf("Create() local-only mode err = %v", err)
		}
	})
}

func TestCreate_PullThenSuccess(t *testing.T) {
	inspectCalls := 0
	d := &fakeDaemon{
		t: t,
		imageInspect: func() *http.Response {
			inspectCalls++
			if inspectCalls == 1 {
				// First inspect misses → triggers a pull.
				return textResponse(http.StatusNotFound, "no such image")
			}
			return jsonResponse(http.StatusOK, map[string]any{
				"Config": map[string]any{"WorkingDir": "", "Entrypoint": []string{"/bin/sh"}, "Cmd": []string{"-c", "sleep"}},
			})
		},
		pull: func() *http.Response {
			return textResponse(http.StatusOK, `{"status":"Pulling"}`+"\n"+`{"status":"done"}`)
		},
		create: func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
		start:  func() *http.Response { return textResponse(http.StatusNoContent, "") },
	}
	c := newCreateClient(t, d, true, nil)

	req := models.CreateSandboxRequest{Image: "registry.example/app:v1"}
	rt, err := c.Create(context.Background(), req, "sb", "tok", nil)
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	if rt.SandboxID != "sb" || rt.ContainerID != "cid" {
		t.Fatalf("Create() runtime = %+v", rt)
	}
}

func TestCreate_ImagePresentFullSuccess(t *testing.T) {
	d := &fakeDaemon{
		t: t,
		imageInspect: func() *http.Response {
			return jsonResponse(http.StatusOK, map[string]any{
				"Config": map[string]any{"WorkingDir": "/app", "Entrypoint": []string{}, "Cmd": []string{}},
			})
		},
		create: func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
		start:  func() *http.Response { return textResponse(http.StatusNoContent, "") },
	}
	c := newCreateClient(t, d, true, func(c *Client) {
		c.network = "custom-net" // exercises the NetworkMode branch
	})

	req := models.CreateSandboxRequest{
		Image:            "registry.example/app:v1",
		CPU:              2,
		MemoryMB:         512,
		DiskGB:           5,
		Env:              map[string]string{"FOO": "bar"},
		ContainerCommand: []string{"/bin/run"},
		NetworkBlockAll:  true,
		GPUs:             &models.GPURequest{Vendor: models.GPUVendorNVIDIA, Count: 2, DeviceIDs: []string{"0", "1"}},
	}
	// containerGet must report an IP on the "custom-net" network so getContainerIP
	// (preferred network) resolves; the default helper uses "bridge", so override.
	ip, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	defer closeFn()
	c.toolboxPort = port
	d.containerGet = func() *http.Response {
		return textResponse(http.StatusOK,
			`{"Id":"cid","Name":"/sb","State":{"Running":true,"Status":"running","Pid":7},"NetworkSettings":{"Networks":{"custom-net":{"IPAddress":"`+ip+`"}}}}`)
	}

	rt, err := c.Create(context.Background(), req, "sb", "tok", []mounts.ContainerBind{
		{HostPath: "/h", ContainerPath: "/c", ReadOnly: true},
		{HostPath: "/h2", ContainerPath: "/c2"},
	})
	if err != nil {
		t.Fatalf("Create() = %v", err)
	}
	if rt.SandboxID != "sb" {
		t.Fatalf("Create() runtime = %+v", rt)
	}
}

func TestCreate_GPUVariants(t *testing.T) {
	cases := []struct {
		name    string
		vendor  models.GPUVendor
		runtime string
		diskGB  int
	}{
		{name: "amd", vendor: models.GPUVendorAMD},
		{name: "apple", vendor: models.GPUVendorApple},
		{name: "gvisor_disk_warn", vendor: "", runtime: models.RuntimeGvisor, diskGB: 5},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := &fakeDaemon{
				t: t,
				imageInspect: func() *http.Response {
					return jsonResponse(http.StatusOK, map[string]any{
						"Config": map[string]any{"WorkingDir": "/", "Entrypoint": []string{"/e"}, "Cmd": []string{}},
					})
				},
				create: func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
				start:  func() *http.Response { return textResponse(http.StatusNoContent, "") },
			}
			c := newCreateClient(t, d, true, nil)
			req := models.CreateSandboxRequest{Image: "img", Runtime: tc.runtime, DiskGB: tc.diskGB}
			if tc.vendor != "" {
				req.GPUs = &models.GPURequest{Vendor: tc.vendor}
			}
			if _, err := c.Create(context.Background(), req, "sb", "tok", nil); err != nil {
				t.Fatalf("Create() = %v", err)
			}
		})
	}
}

func TestCreate_FailurePaths(t *testing.T) {
	imagePresent := func() *http.Response {
		return jsonResponse(http.StatusOK, map[string]any{
			"Config": map[string]any{"WorkingDir": "/", "Entrypoint": []string{"/e"}, "Cmd": []string{}},
		})
	}

	t.Run("pull_error", func(t *testing.T) {
		d := &fakeDaemon{
			t:            t,
			imageInspect: func() *http.Response { return textResponse(http.StatusNotFound, "no such image") },
			pull: func() *http.Response {
				return textResponse(http.StatusOK, `{"errorDetail":{"message":"manifest unknown"}}`)
			},
		}
		c := newCreateClient(t, d, true, nil)
		if _, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "registry.example/x:v1"}, "sb", "tok", nil); err == nil {
			t.Fatal("Create() expected pull error")
		}
	})

	t.Run("inspect_after_pull_error", func(t *testing.T) {
		first := true
		d := &fakeDaemon{
			t: t,
			imageInspect: func() *http.Response {
				if first {
					first = false
					return textResponse(http.StatusNotFound, "no such image")
				}
				return textResponse(http.StatusInternalServerError, "boom")
			},
			pull: func() *http.Response { return textResponse(http.StatusOK, `{"status":"done"}`) },
		}
		c := newCreateClient(t, d, true, nil)
		if _, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "registry.example/x:v1"}, "sb", "tok", nil); err == nil {
			t.Fatal("Create() expected post-pull inspect error")
		}
	})

	t.Run("create_container_error", func(t *testing.T) {
		d := &fakeDaemon{
			t:            t,
			imageInspect: imagePresent,
			create:       func() *http.Response { return textResponse(http.StatusInternalServerError, "boom") },
		}
		c := newCreateClient(t, d, true, nil)
		if _, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb", "tok", nil); err == nil {
			t.Fatal("Create() expected create error")
		}
	})

	t.Run("start_error_rolls_back", func(t *testing.T) {
		d := &fakeDaemon{
			t:            t,
			imageInspect: imagePresent,
			create:       func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
			start:        func() *http.Response { return textResponse(http.StatusInternalServerError, "boom") },
		}
		c := newCreateClient(t, d, true, nil)
		if _, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb", "tok", nil); err == nil {
			t.Fatal("Create() expected start error")
		}
		if d.removeCalls == 0 {
			t.Fatal("Create() should roll back the container on start failure")
		}
	})

	t.Run("wait_runtime_inspect_error_rolls_back", func(t *testing.T) {
		d := &fakeDaemon{
			t:            t,
			imageInspect: imagePresent,
			create:       func() *http.Response { return jsonResponse(http.StatusCreated, map[string]string{"Id": "cid"}) },
			start:        func() *http.Response { return textResponse(http.StatusNoContent, "") },
			containerGet: func() *http.Response { return textResponse(http.StatusInternalServerError, "boom") },
		}
		c := newCreateClient(t, d, true, nil)
		if _, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb", "tok", nil); err == nil {
			t.Fatal("Create() expected waitForRuntime inspect error")
		}
		if d.removeCalls == 0 {
			t.Fatal("Create() should roll back on waitForRuntime failure")
		}
	})
}

func TestStartAndWaitForRuntime(t *testing.T) {
	t.Run("start_success", func(t *testing.T) {
		ip, port, closeFn := toolboxServer(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
		defer closeFn()
		d := &fakeDaemon{
			t:     t,
			start: func() *http.Response { return textResponse(http.StatusNoContent, "") },
			containerGet: func() *http.Response {
				return textResponse(http.StatusOK, inspectBody("cid", "/sb", ip, true, "running", 7))
			},
		}
		c := &Client{
			httpClient:         &http.Client{Transport: d.transport()},
			toolboxClient:      &http.Client{Timeout: 2 * time.Second},
			toolboxPort:        port,
			waitTimeout:        2 * time.Second,
			toolboxWaitTimeout: 2 * time.Second,
		}
		rt, err := c.Start(context.Background(), "sb")
		if err != nil {
			t.Fatalf("Start() = %v", err)
		}
		if rt.ContainerIP != ip {
			t.Fatalf("Start() ip = %q", rt.ContainerIP)
		}
	})

	t.Run("start_error", func(t *testing.T) {
		c := &Client{httpClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return textResponse(http.StatusInternalServerError, "boom"), nil
		})}}
		if _, err := c.Start(context.Background(), "sb"); err == nil {
			t.Fatal("Start() expected error")
		}
	})

	t.Run("wait_timeout_not_running", func(t *testing.T) {
		d := &fakeDaemon{
			t: t,
			containerGet: func() *http.Response {
				return textResponse(http.StatusOK, inspectBody("cid", "/sb", "", false, "created", 0))
			},
		}
		c := &Client{
			httpClient:  &http.Client{Transport: d.transport()},
			waitTimeout: 5 * time.Millisecond,
		}
		if _, err := c.waitForRuntime(context.Background(), "cid"); err == nil {
			t.Fatal("waitForRuntime() expected timeout")
		}
	})
}
