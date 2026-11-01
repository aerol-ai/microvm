package e2b

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestRuntimeProxyEndsWhenSandboxStops: an envd request (a command stream)
// in flight when its sandbox stops ends at once with E2B's 502, which the
// E2B SDK reads as "the sandbox was not found", instead of waiting on a
// connection the sandbox will never answer.
func TestRuntimeProxyEndsWhenSandboxStops(t *testing.T) {
	arrived := make(chan struct{}, 1)
	envd := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		<-r.Context().Done() // a command that is still running
	}))
	defer envd.Close()
	_, portText, _ := net.SplitHostPort(envd.Listener.Addr().String())
	port, _ := strconv.Atoi(portText)

	svc, st, handler := newE2BHandlerTestEnvWithRuntime(t, newFakeE2BRuntime(),
		config.Config{PublicHost: "sandbox.test", EnableCaddy: false, ToolboxPort: port})
	id := createE2BSandbox(t, handler)
	ctx := context.Background()
	blob, _ := json.Marshal(compatBlob{Secure: false, OnTimeout: "kill"})
	if err := st.UpsertCompatState(ctx, id, "e2b", string(blob)); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateStatus(ctx, id, models.SandboxStatusStarted, ""); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateRuntime(ctx, id, id, "127.0.0.1", ""); err != nil {
		t.Fatal(err)
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPost, "/e2b/runtime/process.Process/Start", nil)
		req.Header.Set("E2b-Sandbox-Id", id)
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		done <- rr
	}()
	select {
	case <-arrived:
	case <-time.After(5 * time.Second):
		t.Fatal("the request never reached envd")
	}
	if _, err := svc.StopSandbox(ctx, id); err != nil {
		t.Fatalf("StopSandbox: %v", err)
	}
	select {
	case rr := <-done:
		if rr.Code != http.StatusBadGateway {
			t.Fatalf("status = %d, want E2B's 502", rr.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the envd request is still waiting on a stopped sandbox")
	}
}
