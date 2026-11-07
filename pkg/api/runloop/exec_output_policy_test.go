package runloop

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ER5 on the Runloop path: Runloop's one-shot commands reach toolboxd's
// buffered exec through RoundTripToolbox, so the operator's default is
// filled in and a larger cap is lowered before toolboxd sees them.
func TestRunloopExecGetsOperatorOutputLimits(t *testing.T) {
	env := newTestEnvWithConfig(t, func(cfg *config.Config) {
		cfg.ExecOutputDefaultBytes = 2048
		cfg.ExecOutputMaxBytes = 8192
	})
	devbox := env.mustCreate(t, "")

	var mu sync.Mutex
	var seen []models.ExecRequest
	env.toolbox.setBeforeServe(func(r *http.Request) {
		if r.URL.Path != "/process/execute" {
			return
		}
		raw, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(raw))
		var req models.ExecRequest
		_ = json.Unmarshal(raw, &req)
		mu.Lock()
		seen = append(seen, req)
		mu.Unlock()
	})
	last := func() models.ExecRequest {
		mu.Lock()
		defer mu.Unlock()
		if len(seen) == 0 {
			t.Fatal("no exec reached the toolbox")
		}
		return seen[len(seen)-1]
	}

	// The $HOME lookup a relative path needs is a one-shot exec with no cap.
	expectStatus(t, env.do(t, http.MethodPost, "/"+devbox.ID+"/write_file_contents", `{"file_path":"rel.txt","contents":"x"}`, nil), http.StatusOK)
	if got := last(); got.MaxStdoutBytes != 2048 || got.MaxStderrBytes != 2048 {
		t.Fatalf("one-shot exec caps = %d/%d, want the 2048 default", got.MaxStdoutBytes, got.MaxStderrBytes)
	}

	// A cap above the maximum on the same path is lowered to it.
	var out models.ExecResult
	if _, err := env.h.toolboxCall(context.Background(), devbox.ID, http.MethodPost, "/process/execute", nil,
		models.ExecRequest{Command: "true", MaxStdoutBytes: 1 << 30, MaxStderrBytes: 100}, &out); err != nil {
		t.Fatal(err)
	}
	if got := last(); got.MaxStdoutBytes != 8192 || got.MaxStderrBytes != 100 {
		t.Fatalf("clamped caps = %d/%d, want 8192/100", got.MaxStdoutBytes, got.MaxStderrBytes)
	}
}
