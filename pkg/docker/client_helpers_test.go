package docker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
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
