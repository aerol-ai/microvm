package containerd_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/internal/service"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/api/apihttp"
	"github.com/aerol-ai/microvm/pkg/caddy"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
	"github.com/aerol-ai/microvm/pkg/secrets"
)

// TestKeyedCreateRetryAfterClientHangUpGetsTheSandbox is UC-450 in process:
// an Idempotency-Key create (CreateSandboxWithID under the key's derived ID,
// which the v1 create runs in single-node mode and the cluster overlap create
// runs on the owner) whose client hangs up while containerd is still making
// the sandbox, then the client's retry under the same key. The retry must
// create the sandbox, not answer 409 "sandbox already exists" because the
// first create's container is still there under the ID with no row.
func TestKeyedCreateRetryAfterClientHangUpGetsTheSandbox(t *testing.T) {
	const id = "sb-uc450"
	req := models.CreateSandboxRequest{
		Name:             "uc450",
		Image:            "alpine:3.20",
		ContainerCommand: []string{"sleep", "inf"},
	}
	for _, at := range []string{"new task", "task start", "readiness wait"} {
		t.Run(at, func(t *testing.T) {
			d, arm := containerd.NewHangUpDriver(t, at)
			svc := newContainerdService(t, d)

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			arm(cancel)
			if _, err := svc.CreateSandboxWithID(ctx, req, id); !errors.Is(err, context.Canceled) {
				t.Fatalf("create the client hung up on: err = %v, want context.Canceled", err)
			}

			resp, err := svc.CreateSandboxWithID(context.Background(), req, id)
			if err != nil {
				c := apihttp.Classify(err)
				t.Fatalf("retry under the same key: %v (HTTP %d %q), want the sandbox", err, c.Status, c.Message)
			}
			if resp.Sandbox.ID != id || resp.Replayed {
				t.Fatalf("retry = %s replayed=%v, want a fresh create of %s", resp.Sandbox.ID, resp.Replayed, id)
			}
			again, err := svc.CreateSandboxWithID(context.Background(), req, id)
			if err != nil || !again.Replayed || again.Sandbox.ID != id {
				t.Fatalf("third call = (%+v, %v), want the replay of %s", again, err, id)
			}
		})
	}
}

func newContainerdService(t *testing.T, d *containerd.Driver) *service.Service {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr, err := mounts.New(logger, mounts.Config{
		RootDir:     filepath.Join(dir, "mounts"),
		CredDir:     filepath.Join(dir, "creds"),
		WaitTimeout: time.Second,
	})
	if err != nil {
		t.Fatalf("mounts.New: %v", err)
	}
	t.Cleanup(mgr.Close)
	cipher, err := secrets.NewCipher("", filepath.Join(dir, "cipher.key"))
	if err != nil {
		t.Fatalf("secrets.NewCipher: %v", err)
	}
	cfg := config.Config{ContainerEngine: models.ContainerEngineContainerd, ToolboxPort: 2280}
	svc := service.New(cfg, logger, st, d, nil, caddy.New(cfg), cipher, mgr, nil)
	svc.SetContainerdRuntime(d)
	return svc
}
