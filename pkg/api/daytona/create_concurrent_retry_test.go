package daytona

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/pkg/models"
)

// A Daytona SDK retry of a keyed create that is still running on the node
// (a proxy 504 while the first create pulls its image) waits for it and
// replays its sandbox: one runtime create, both answers name the same
// sandbox. A retry with the same key and a different request is refused at
// once, without waiting and without touching the running create.
func TestDaytonaConcurrentKeyedRetries(t *testing.T) {
	const body = `{"snapshot":"alpine:3.20","env":{"K":"1"}}`
	env := newDaytonaContractEnv(t)
	env.runtime.hold, env.runtime.entered = make(chan struct{}), make(chan struct{})
	h := &handlers{deps: Deps{Service: env.service, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))}}

	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- daytonaPost(t, h, "job-77", body) }()
	<-env.runtime.entered

	const retries = 3
	retried := make(chan *httptest.ResponseRecorder, retries)
	for range retries {
		go func() { retried <- daytonaPost(t, h, "job-77", body) }()
	}
	refused := make(chan *httptest.ResponseRecorder, 1)
	go func() { refused <- daytonaPost(t, h, "job-77", `{"snapshot":"alpine:3.21"}`) }()
	select {
	case rr := <-refused:
		var body models.ErrorResponse
		if rr.Code != http.StatusUnprocessableEntity || json.Unmarshal(rr.Body.Bytes(), &body) != nil || body.Code != models.ErrorCodeIdempotencyKeyReused {
			t.Fatalf("different request = %d %s, want 422 idempotency_key_reused", rr.Code, rr.Body.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a different request waited for the running create")
	}
	time.Sleep(50 * time.Millisecond)
	env.runtime.mu.Lock()
	creating := env.runtime.creates
	env.runtime.mu.Unlock()
	if creating != 1 {
		t.Fatalf("runtime creates while the first runs = %d, want 1", creating)
	}
	close(env.runtime.hold)

	var created sandboxResponse
	rr := <-first
	if rr.Code != http.StatusCreated || json.Unmarshal(rr.Body.Bytes(), &created) != nil || created.ID == "" {
		t.Fatalf("first create = %d %s", rr.Code, rr.Body.String())
	}
	for range retries {
		rr := <-retried
		var again sandboxResponse
		_ = json.Unmarshal(rr.Body.Bytes(), &again)
		if rr.Code != http.StatusCreated || again.ID != created.ID {
			t.Fatalf("retry = %d %s; want a replay of %s", rr.Code, rr.Body.String(), created.ID)
		}
	}
	env.runtime.mu.Lock()
	defer env.runtime.mu.Unlock()
	if env.runtime.creates != 1 {
		t.Fatalf("runtime creates = %d, want exactly 1", env.runtime.creates)
	}
	if n := countSandboxes(t, env); n != 1 {
		t.Fatalf("sandbox count = %d, want 1", n)
	}
	if _, err := env.service.GetSandbox(t.Context(), created.ID); err != nil {
		t.Fatalf("the sandbox is gone: %v", err)
	}
}
