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
	for _, at := range []string{"new container", "new task", "task start", "readiness wait"} {
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

type keyedCreateResult struct {
	resp *models.CreateSandboxResponse
	err  error
}

// TestKeyedCreateRetrySentWhileTheFirstRunsGetsOneSandbox is UC-450 as the
// live run of 2026-11-08 met it: the client gives up while containerd is
// inside NewContainer and at once sends the same keyed create again, which
// reaches the node while the first create still runs. The retry waits for
// the first create (the ID's create lease), which fails and undoes itself;
// then the retry must create the one sandbox of that name, not answer 409
// "sandbox already exists" because the first create's snapshot is still
// there under the ID.
func TestKeyedCreateRetrySentWhileTheFirstRunsGetsOneSandbox(t *testing.T) {
	const id = "sb-uc450"
	req := models.CreateSandboxRequest{
		Name:             "uc450",
		Image:            "alpine:3.20",
		ContainerCommand: []string{"sleep", "inf"},
	}
	d, arm := containerd.NewHangUpDriver(t, "new container")
	svc := newContainerdService(t, d)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	retried := make(chan keyedCreateResult, 1)
	arm(func() {
		go func() {
			resp, err := svc.CreateSandboxWithID(context.Background(), req, id)
			retried <- keyedCreateResult{resp, err}
		}()
		// Give the retry time to reach the lease the first create holds.
		time.Sleep(50 * time.Millisecond)
		cancel()
	})
	if _, err := svc.CreateSandboxWithID(ctx, req, id); !errors.Is(err, context.Canceled) {
		t.Fatalf("create the client hung up on: err = %v, want context.Canceled", err)
	}

	var got keyedCreateResult
	select {
	case got = <-retried:
	case <-time.After(30 * time.Second):
		t.Fatal("the retry never finished")
	}
	if got.err != nil {
		c := apihttp.Classify(got.err)
		t.Fatalf("retry sent while the first create ran: %v (HTTP %d %q), want the sandbox", got.err, c.Status, c.Message)
	}
	if got.resp.Sandbox.ID != id || got.resp.Replayed {
		t.Fatalf("retry = %s replayed=%v, want a fresh create of %s", got.resp.Sandbox.ID, got.resp.Replayed, id)
	}
	byName, err := svc.ListSandboxesByName(context.Background(), req.Name, nil, service.GetSandboxOptions{})
	if err != nil || len(byName) != 1 || byName[0].ID != id {
		t.Fatalf("sandboxes named %q = (%d, %v), want the one sandbox %s", req.Name, len(byName), err, id)
	}
	again, err := svc.CreateSandboxWithID(context.Background(), req, id)
	if err != nil || !again.Replayed || again.Sandbox.ID != id {
		t.Fatalf("third call = (%+v, %v), want the replay of %s", again, err, id)
	}
}

// TestKeyedCreateRetryRemovesASnapshotLeftWithoutItsContainer: the snapshot a
// hung-up NewContainer leaves can appear after that create's undo has looked
// (containerd finishes the prepare after the client is gone). The retry then
// meets it as AlreadyExists, and the service's leftover removal destroys the
// ID and creates again. Destroy used to see no container and do nothing, so
// the second create met the same snapshot and the retry got 409.
func TestKeyedCreateRetryRemovesASnapshotLeftWithoutItsContainer(t *testing.T) {
	const id = "sb-uc450"
	req := models.CreateSandboxRequest{
		Name:             "uc450",
		Image:            "alpine:3.20",
		ContainerCommand: []string{"sleep", "inf"},
	}
	svc := newContainerdService(t, containerd.NewLeftoverSnapshotDriver(t, id))
	resp, err := svc.CreateSandboxWithID(context.Background(), req, id)
	if err != nil {
		c := apihttp.Classify(err)
		t.Fatalf("keyed create over a leftover snapshot: %v (HTTP %d %q), want the sandbox", err, c.Status, c.Message)
	}
	if resp.Sandbox.ID != id || resp.Replayed {
		t.Fatalf("create = %s replayed=%v, want a fresh create of %s", resp.Sandbox.ID, resp.Replayed, id)
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
