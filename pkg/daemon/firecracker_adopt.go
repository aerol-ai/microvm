package daemon

import (
	"context"
	"errors"

	fcruntime "github.com/aerol-ai/microvm/internal/runtime/firecracker"
	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/models"
)

// sandboxGetter is the store read firecrackerVMKeeper needs.
type sandboxGetter interface {
	Get(ctx context.Context, id string) (*models.Sandbox, error)
}

// firecrackerVMKeeper answers, for a VM a previous sandboxd left running,
// whether its sandbox should still be running here: a Firecracker sandbox
// this node holds that is not stopped, passivated or destroyed. One in
// creating or error keeps its VM too, so the reconcile or destroy that
// settles it has a VM to stop.
func firecrackerVMKeeper(db sandboxGetter) fcruntime.VMMKeeper {
	return func(ctx context.Context, sandboxID string) (bool, error) {
		sandbox, err := db.Get(ctx, sandboxID)
		if errors.Is(err, store.ErrNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if sandbox.Runtime != models.RuntimeFirecracker {
			return false, nil
		}
		switch sandbox.Status {
		case models.SandboxStatusStopped, models.SandboxStatusPassivated, models.SandboxStatusDestroyed:
			return false, nil
		}
		return true, nil
	}
}
