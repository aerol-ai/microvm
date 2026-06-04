package docker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestClientHelperFunctions(t *testing.T) {
	t.Run("is_local_only_image_ref", func(t *testing.T) {
		if !IsLocalOnlyImageRef(BuiltImageNamespace + "/abc:latest") {
			t.Fatalf("expected built image namespace to be local-only")
		}
		if !IsLocalOnlyImageRef("snapshots/base:v1") {
			t.Fatalf("expected snapshots/* to be local-only")
		}
		if IsLocalOnlyImageRef("ubuntu:22.04") {
			t.Fatalf("expected regular registry image to not be local-only")
		}
	})

	t.Run("acquire_and_release_pull_slot", func(t *testing.T) {
		c := &Client{pullSlots: make(chan struct{}, 1)}
		acquired, err := c.acquirePullSlot(context.Background())
		if err != nil || !acquired {
			t.Fatalf("acquirePullSlot() acquired=%v err=%v", acquired, err)
		}
		c.releasePullSlot()
		select {
		case <-c.pullSlots:
			t.Fatalf("pull slot should have been released")
		default:
		}
	})

	t.Run("acquire_pull_slot_context_canceled", func(t *testing.T) {
		c := &Client{pullSlots: make(chan struct{}, 1)}
		c.pullSlots <- struct{}{}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		acquired, err := c.acquirePullSlot(ctx)
		if acquired {
			t.Fatalf("expected acquirePullSlot to return acquired=false")
		}
		if err == nil {
			t.Fatalf("expected context cancellation error")
		}
	})

	t.Run("image_pull_key", func(t *testing.T) {
		if got := imagePullKey("  ubuntu:22.04  ", nil); got != "ubuntu:22.04" {
			t.Fatalf("imagePullKey without auth = %q", got)
		}
		auth := &models.RegistryAuth{Server: " ghcr.io ", Username: " alice "}
		if got := imagePullKey(" repo/img:v1 ", auth); got != "repo/img:v1\x00ghcr.io\x00alice" {
			t.Fatalf("imagePullKey with auth = %q", got)
		}
	})

	t.Run("get_container_ip", func(t *testing.T) {
		inspect := containerInspect{}
		inspect.NetworkSettings.Networks = map[string]struct {
			IPAddress string "json:\"IPAddress\""
		}{
			"bridge": {IPAddress: "172.17.0.2"},
			"custom": {IPAddress: "10.0.0.4"},
		}
		if got := getContainerIP(inspect, "custom"); got != "10.0.0.4" {
			t.Fatalf("preferred network IP = %q", got)
		}
		if got := getContainerIP(inspect, "missing"); got == "" {
			t.Fatalf("expected fallback non-empty IP")
		}
		empty := containerInspect{}
		empty.NetworkSettings.Networks = map[string]struct {
			IPAddress string "json:\"IPAddress\""
		}{}
		if got := getContainerIP(empty, "bridge"); got != "" {
			t.Fatalf("expected empty IP, got %q", got)
		}
	})

	t.Run("container_status", func(t *testing.T) {
		if got := containerStatus(containerInspect{}); got != models.SandboxStatusError {
			t.Fatalf("nil state status = %q", got)
		}
		running := containerInspect{}
		running.State = &struct {
			Running bool   "json:\"Running\""
			Status  string "json:\"Status\""
			Pid     int    "json:\"Pid\""
		}{Running: true, Status: "running"}
		if got := containerStatus(running); got != models.SandboxStatusStarted {
			t.Fatalf("running status = %q", got)
		}
		exited := containerInspect{}
		exited.State = &struct {
			Running bool   "json:\"Running\""
			Status  string "json:\"Status\""
			Pid     int    "json:\"Pid\""
		}{Running: false, Status: "exited"}
		if got := containerStatus(exited); got != models.SandboxStatusStopped {
			t.Fatalf("exited status = %q", got)
		}
	})

	t.Run("inspect_helpers", func(t *testing.T) {
		httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/containers/sb-1/json" {
				payload, _ := json.Marshal(containerInspect{ID: "cid-1", Name: "/sb-1"})
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(payload))), Header: make(http.Header)}, nil
			}
			if strings.HasPrefix(r.URL.Path, "/images/") && strings.HasSuffix(r.URL.Path, "/json") {
				payload, _ := json.Marshal(imageInspect{})
				return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(payload))), Header: make(http.Header)}, nil
			}
			return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("missing")), Header: make(http.Header)}, nil
		})}
		c := &Client{httpClient: httpClient}
		ins, err := c.inspectContainer(context.Background(), "sb-1")
		if err != nil || ins.ID != "cid-1" {
			t.Fatalf("inspectContainer() id=%q err=%v", ins.ID, err)
		}
		if _, err := c.inspectImage(context.Background(), "repo/img:latest"); err != nil {
			t.Fatalf("inspectImage() err=%v", err)
		}
	})

	t.Run("wait_for_toolbox_success", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))
		defer server.Close()

		hostPort := strings.TrimPrefix(server.URL, "http://")
		parts := strings.Split(hostPort, ":")
		port, err := strconv.Atoi(parts[len(parts)-1])
		if err != nil {
			t.Fatalf("parse port: %v", err)
		}

		c := &Client{
			toolboxClient:      server.Client(),
			toolboxPort:        port,
			toolboxWaitTimeout: 2 * time.Second,
		}
		if err := c.waitForToolbox(context.Background(), "127.0.0.1"); err != nil {
			t.Fatalf("waitForToolbox() error = %v", err)
		}
	})

	t.Run("wait_for_toolbox_timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer server.Close()

		hostPort := strings.TrimPrefix(server.URL, "http://")
		parts := strings.Split(hostPort, ":")
		port, err := strconv.Atoi(parts[len(parts)-1])
		if err != nil {
			t.Fatalf("parse port: %v", err)
		}

		c := &Client{
			toolboxClient:      server.Client(),
			toolboxPort:        port,
			toolboxWaitTimeout: 350 * time.Millisecond,
		}
		if err := c.waitForToolbox(context.Background(), "127.0.0.1"); err == nil {
			t.Fatalf("expected timeout error")
		}
	})
}
