package service

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// syncWriter lets the event goroutine and the test share a log buffer.
type syncWriter struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *syncWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}
func (w *syncWriter) String() string { w.mu.Lock(); defer w.mu.Unlock(); return w.b.String() }

// The API destroy removes the container, which fires the runtime's destroy
// event while DestroySandbox is still finalizing. The event must wait it out
// and then do nothing: before, it raced the API path through the cluster
// placement delete and failed on the placement just removed, once per destroy
// on every Docker 29 node (105 warnings in one cluster-3-mixed-docker run).
func TestDestroyEventWaitsOutAnAPIDestroy(t *testing.T) {
	ctx := context.Background()
	svc, _, st := newCapacityHarness(t, nil, nil)
	logs := &syncWriter{}
	svc.logger = slog.New(slog.NewTextHandler(logs, nil))

	const id = "sb-destroy-race"
	seedSandbox(t, st, id, models.SandboxStatusStarted, 1, 512)

	unlock := svc.destroyLocks.lock(id) // an API destroy in flight
	done := make(chan error, 1)
	go func() {
		done <- svc.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: id, Action: "destroy", Time: time.Now().UTC()})
	}()
	select {
	case err := <-done:
		t.Fatalf("the destroy event ran alongside an API destroy (err=%v)", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := st.Delete(ctx, id); err != nil { // the API path finishes
		t.Fatal(err)
	}
	unlock()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("destroy event after the API destroy: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the destroy event never ran after the API destroy finished")
	}
	if strings.Contains(logs.String(), "destroyed via docker event") {
		t.Fatalf("the event re-ran a destroy the API path had finished:\n%s", logs.String())
	}

	// With no API destroy in flight, the event still tears down a container
	// removed outside the API (docker rm -f).
	seedSandbox(t, st, id+"-oob", models.SandboxStatusStarted, 1, 512)
	if err := svc.handleDockerEvent(ctx, docker.DockerEvent{SandboxID: id + "-oob", Action: "destroy", Time: time.Now().UTC()}); err != nil {
		t.Fatalf("out-of-band destroy event: %v", err)
	}
	if !strings.Contains(logs.String(), "destroyed via docker event") {
		t.Fatal("an out-of-band destroy was not handled")
	}
}
