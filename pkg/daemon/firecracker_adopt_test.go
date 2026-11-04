package daemon

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

type fakeSandboxGetter map[string]*models.Sandbox

func (f fakeSandboxGetter) Get(_ context.Context, id string) (*models.Sandbox, error) {
	if id == "sb-broken" {
		return nil, errors.New("database is locked")
	}
	sandbox, ok := f[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	return sandbox, nil
}

// Only a Firecracker sandbox that should be running keeps the VM a previous
// sandboxd left; a store that cannot answer is an error, not a "no".
func TestFirecrackerVMKeeper(t *testing.T) {
	fc := func(status models.SandboxStatus) *models.Sandbox {
		return &models.Sandbox{Runtime: models.RuntimeFirecracker, Status: status}
	}
	keep := firecrackerVMKeeper(fakeSandboxGetter{
		"sb-started":    fc(models.SandboxStatusStarted),
		"sb-creating":   fc(models.SandboxStatusCreating),
		"sb-error":      fc(models.SandboxStatusError),
		"sb-stopped":    fc(models.SandboxStatusStopped),
		"sb-passivated": fc(models.SandboxStatusPassivated),
		"sb-destroyed":  fc(models.SandboxStatusDestroyed),
		"sb-docker":     {Runtime: models.RuntimeDocker, Status: models.SandboxStatusStarted},
	})
	for id, want := range map[string]bool{
		"sb-started": true, "sb-creating": true, "sb-error": true,
		"sb-stopped": false, "sb-passivated": false, "sb-destroyed": false,
		"sb-docker": false, "sb-missing": false,
	} {
		got, err := keep(context.Background(), id)
		if err != nil || got != want {
			t.Errorf("%s: keep = %v, %v; want %v", id, got, err, want)
		}
	}
	if _, err := keep(context.Background(), "sb-broken"); err == nil {
		t.Fatal("a store error was answered")
	}
}
