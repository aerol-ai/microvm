package docker

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// The 2026-11-02 density run's failure shape: dockerd created the container,
// then its start failed attaching the veth to a bridge that already held
// 1,023 ports. The driver must remove the half-created container (the bridge
// port was never taken, but the container and its name were), and pass the
// kernel's "exchange full" up so the service can answer it as a capacity
// refusal.
func TestCreateRemovesContainerWhenTheBridgeIsFull(t *testing.T) {
	d := fakeCreateDaemon(t)
	d.start = func() *http.Response {
		return textResponse(http.StatusInternalServerError,
			`{"message":"failed to set up container networking: adding interface veth5f0e1a2 to bridge docker0 failed: exchange full"}`)
	}
	c := newCreateClient(t, d, true, nil)
	_, err := c.Create(context.Background(), models.CreateSandboxRequest{Image: "img"}, "sb-full", "tok", nil)
	if err == nil {
		t.Fatal("create on a full bridge succeeded")
	}
	if !strings.Contains(err.Error(), "start container") || !strings.Contains(err.Error(), "exchange full") {
		t.Fatalf("error %q lost the start failure or its cause", err)
	}
	if d.removeCalls != 1 {
		t.Fatalf("half-created container removed %d times, want 1", d.removeCalls)
	}
}
