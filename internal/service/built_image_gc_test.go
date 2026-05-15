package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/aerol-ai/microvm/internal/config"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/pkg/mounts"
)

// newBuiltImageGCHarness builds the minimum Service surface the janitor
// needs: a real Store (so HasActiveImageRef hits the indexed SQL path) and
// a counting fake runtime so we can assert which tags got RemoveImage'd.
// Everything else stays zero — the GC pass only touches store + docker.
func newBuiltImageGCHarness(t *testing.T, ttl time.Duration) (*Service, *store.Store, *[]string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	removed := []string{}
	rt := &recordingRemoveRuntime{removed: &removed}

	svc := &Service{
		cfg: config.Config{
			ImageBuildGCEnabled: true,
			ImageBuildGCTTL:     ttl,
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
		docker: rt,
	}
	return svc, st, &removed
}

// recordingRemoveRuntime is a runtime.Runtime stub that captures every
// RemoveImage call. The other methods panic so this stub is hard to misuse:
// the GC must only touch RemoveImage.
type recordingRemoveRuntime struct {
	removed   *[]string
	removeErr error
}

func (r *recordingRemoveRuntime) RemoveImage(_ context.Context, ref string) error {
	*r.removed = append(*r.removed, ref)
	return r.removeErr
}

func (*recordingRemoveRuntime) Create(context.Context, models.CreateSandboxRequest, string, string, []mounts.ContainerBind) (*models.SandboxRuntimeState, error) {
	panic("Create not used by GC tests")
}

// The runtime.Runtime interface requires more methods than we use here. We
// only define RemoveImage above and panic on every other method so this
// stub is hard to misuse — the GC must touch RemoveImage and nothing else.
func (*recordingRemoveRuntime) Start(context.Context, string) (*models.SandboxRuntimeState, error) {
	panic("Start not used")
}
func (*recordingRemoveRuntime) Stop(context.Context, string) error { panic("Stop not used") }
func (*recordingRemoveRuntime) Destroy(context.Context, *models.Sandbox) error {
	panic("Destroy not used")
}
func (*recordingRemoveRuntime) CreateSnapshot(context.Context, string, string) (string, error) {
	panic("CreateSnapshot not used")
}
func (*recordingRemoveRuntime) Resize(context.Context, string, models.ResizeSandboxRequest) error {
	panic("Resize not used")
}
func (*recordingRemoveRuntime) Inspect(context.Context, string) (*models.SandboxRuntimeState, error) {
	panic("Inspect not used")
}
func (*recordingRemoveRuntime) ListManaged(context.Context) (map[string]*models.SandboxRuntimeState, error) {
	panic("ListManaged not used")
}
func (*recordingRemoveRuntime) Ping(context.Context) error { panic("Ping not used") }
func (*recordingRemoveRuntime) PushAllowedPorts(context.Context, string, string, []int) error {
	panic("PushAllowedPorts not used")
}
func (*recordingRemoveRuntime) ClearNetworkRules(string) error        { panic("not used") }
func (*recordingRemoveRuntime) ApplyNetworkBlockAll(string) error     { panic("not used") }
func (*recordingRemoveRuntime) ApplyNetworkBlockIngress(string) error { panic("not used") }
func (*recordingRemoveRuntime) ClearNetworkBlockIngress(string) error { panic("not used") }
func (*recordingRemoveRuntime) ClearNetworkBlockEgress(string) error  { panic("not used") }

func TestBuiltImageGCRemovesOldUnreferenced(t *testing.T) {
	svc, _, removed := newBuiltImageGCHarness(t, time.Hour)
	old := time.Now().UTC().Add(-2 * time.Hour)
	list := func(context.Context) ([]docker.BuiltImage, error) {
		return []docker.BuiltImage{{Tag: "aerolvm-build/old1:latest", LastTagTime: old}}, nil
	}

	svc.runBuiltImageGC(context.Background(), list)

	if len(*removed) != 1 || (*removed)[0] != "aerolvm-build/old1:latest" {
		t.Fatalf("expected removal of old1, got %+v", *removed)
	}
}

func TestBuiltImageGCSkipsFreshImage(t *testing.T) {
	svc, _, removed := newBuiltImageGCHarness(t, time.Hour)
	fresh := time.Now().UTC().Add(-5 * time.Minute) // well within TTL
	list := func(context.Context) ([]docker.BuiltImage, error) {
		return []docker.BuiltImage{{Tag: "aerolvm-build/fresh:latest", LastTagTime: fresh}}, nil
	}

	svc.runBuiltImageGC(context.Background(), list)

	if len(*removed) != 0 {
		t.Fatalf("fresh image must NOT be removed (within TTL), got %+v", *removed)
	}
}

func TestBuiltImageGCSkipsReferencedImage(t *testing.T) {
	svc, st, removed := newBuiltImageGCHarness(t, time.Hour)
	old := time.Now().UTC().Add(-2 * time.Hour)
	referencedTag := "aerolvm-build/inuse:latest"

	// Seed a sandbox row that pins the image.
	now := time.Now().UTC()
	if err := st.Create(context.Background(), &models.Sandbox{
		ID:        "sb-uses-built",
		Image:     referencedTag,
		Status:    models.SandboxStatusStarted,
		CPU:       1,
		MemoryMB:  1024,
		Runtime:   models.RuntimeDocker,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	list := func(context.Context) ([]docker.BuiltImage, error) {
		return []docker.BuiltImage{{Tag: referencedTag, LastTagTime: old}}, nil
	}
	svc.runBuiltImageGC(context.Background(), list)

	if len(*removed) != 0 {
		t.Fatalf("referenced image must NOT be removed, got %+v", *removed)
	}
}

func TestBuiltImageGCMixedRulesAppliedPerImage(t *testing.T) {
	svc, st, removed := newBuiltImageGCHarness(t, time.Hour)
	old := time.Now().UTC().Add(-2 * time.Hour)
	fresh := time.Now().UTC().Add(-10 * time.Minute)
	now := time.Now().UTC()

	// "inuse" is old AND referenced -> survives.
	if err := st.Create(context.Background(), &models.Sandbox{
		ID:        "sb-pinner",
		Image:     "aerolvm-build/inuse:latest",
		Status:    models.SandboxStatusStarted,
		CPU:       1,
		MemoryMB:  1024,
		Runtime:   models.RuntimeDocker,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	list := func(context.Context) ([]docker.BuiltImage, error) {
		return []docker.BuiltImage{
			{Tag: "aerolvm-build/old-orphan:latest", LastTagTime: old},   // remove
			{Tag: "aerolvm-build/fresh-orphan:latest", LastTagTime: fresh}, // skip (fresh)
			{Tag: "aerolvm-build/inuse:latest", LastTagTime: old},          // skip (referenced)
		}, nil
	}
	svc.runBuiltImageGC(context.Background(), list)

	if len(*removed) != 1 || (*removed)[0] != "aerolvm-build/old-orphan:latest" {
		t.Fatalf("expected exactly old-orphan removed, got %+v", *removed)
	}
}

// A destroyed sandbox row must NOT count as an active reference — otherwise
// the janitor could never reclaim the image after the last user destroyed
// their sandbox. This mirrors the contract HasActiveImageRef advertises.
func TestBuiltImageGCRemovesAfterDestroyedReference(t *testing.T) {
	svc, st, removed := newBuiltImageGCHarness(t, time.Hour)
	old := time.Now().UTC().Add(-2 * time.Hour)
	now := time.Now().UTC()
	tag := "aerolvm-build/once-used:latest"

	if err := st.Create(context.Background(), &models.Sandbox{
		ID:        "sb-historical",
		Image:     tag,
		Status:    models.SandboxStatusDestroyed,
		CPU:       1,
		MemoryMB:  1024,
		Runtime:   models.RuntimeDocker,
		CreatedAt: now,
		UpdatedAt: now,
	}); err != nil {
		t.Fatalf("seed sandbox: %v", err)
	}

	list := func(context.Context) ([]docker.BuiltImage, error) {
		return []docker.BuiltImage{{Tag: tag, LastTagTime: old}}, nil
	}
	svc.runBuiltImageGC(context.Background(), list)

	if len(*removed) != 1 || (*removed)[0] != tag {
		t.Fatalf("expected removal after destroyed reference, got %+v", *removed)
	}
}

func TestBuiltImageGCSwallowsListError(t *testing.T) {
	svc, _, removed := newBuiltImageGCHarness(t, time.Hour)
	list := func(context.Context) ([]docker.BuiltImage, error) {
		return nil, errors.New("docker unreachable")
	}
	// Must not panic; must not call RemoveImage when list fails.
	svc.runBuiltImageGC(context.Background(), list)
	if len(*removed) != 0 {
		t.Fatalf("list error must short-circuit; removed=%+v", *removed)
	}
}

// StartBuiltImageGC must respect the operator kill-switch: if disabled, no
// goroutine should fire even when called. The tick interval is irrelevant
// because the goroutine is never started.
func TestStartBuiltImageGCDisabledIsNoOp(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	svc := &Service{
		cfg:    config.Config{ImageBuildGCEnabled: false},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		store:  st,
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	svc.StartBuiltImageGC(ctx) // returns immediately, no goroutine
	// Nothing to assert beyond "does not panic and returns".
}
