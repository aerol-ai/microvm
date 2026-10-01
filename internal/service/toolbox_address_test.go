package service

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	storepkg "github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// addressingRuntime is a recordingRuntime that also answers ToolboxAddress,
// the way pkg/docker does under SB_DOCKER_TOOLBOX_LOOPBACK.
type addressingRuntime struct {
	*recordingRuntime
	addr  string
	err   error
	asked []string
}

func (a *addressingRuntime) ToolboxAddress(_ context.Context, sb *models.Sandbox) (string, error) {
	a.asked = append(a.asked, sb.ID)
	return a.addr, a.err
}

func seedToolboxSandbox(t *testing.T, st *storepkg.Store) {
	t.Helper()
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID:           "sb-tbx",
		Image:        "alpine",
		Status:       models.SandboxStatusStarted,
		Runtime:      models.RuntimeDocker,
		ContainerID:  "ctr-tbx",
		ContainerIP:  "192.0.2.10",
		ToolboxToken: "tok-tbx",
		CPU:          1,
		MemoryMB:     256,
		DiskGB:       5,
		CreatedAt:    now,
		UpdatedAt:    now,
		LastActiveAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}
}

func TestToolboxTargetAddress(t *testing.T) {
	ctx := context.Background()

	t.Run("default_is_container_ip_and_toolbox_port", func(t *testing.T) {
		svc, st, _ := newServiceRuntimeHarness(t, &recordingRuntime{})
		seedToolboxSandbox(t, st)
		svc.cfg.ToolboxPort = 4242
		ep, err := svc.ToolboxTarget(ctx, "sb-tbx")
		if err != nil {
			t.Fatalf("ToolboxTarget() = %v", err)
		}
		if ep.URL != "http://192.0.2.10:4242" || ep.Token != "tok-tbx" {
			t.Fatalf("ToolboxTarget() = %+v", ep)
		}
	})

	t.Run("runtime_address_wins", func(t *testing.T) {
		rt := &addressingRuntime{recordingRuntime: &recordingRuntime{}, addr: "127.0.0.1:49153"}
		svc, st, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
		seedToolboxSandbox(t, st)
		svc.cfg.ToolboxPort = 4242
		ep, err := svc.ToolboxTarget(ctx, "sb-tbx")
		if err != nil {
			t.Fatalf("ToolboxTarget() = %v", err)
		}
		if ep.URL != "http://127.0.0.1:49153" || ep.Token != "tok-tbx" {
			t.Fatalf("ToolboxTarget() = %+v, want the runtime's loopback address", ep)
		}
		if len(rt.asked) != 1 || rt.asked[0] != "sb-tbx" {
			t.Fatalf("runtime asked for %v, want [sb-tbx]", rt.asked)
		}
	})

	t.Run("runtime_error_surfaces", func(t *testing.T) {
		boom := errors.New("toolbox port is not published")
		rt := &addressingRuntime{recordingRuntime: &recordingRuntime{}, err: boom}
		svc, st, _ := newServiceRuntimeHarnessAtPath(t, filepath.Join(t.TempDir(), "state.db"), rt)
		seedToolboxSandbox(t, st)
		if _, err := svc.ToolboxTarget(ctx, "sb-tbx"); !errors.Is(err, boom) {
			t.Fatalf("ToolboxTarget() error = %v, want %v", err, boom)
		}
	})
}
