package firecracker

import (
	"context"
	"os"

	"github.com/aerol-ai/microvm/pkg/firecracker"
)

type selectivePatchErrClient struct {
	*fakeClient
	failDriveID string
}

func (c *selectivePatchErrClient) PatchDrive(ctx context.Context, id string, patch firecracker.DrivePatch) error {
	if id == c.failDriveID {
		return os.ErrPermission
	}
	return c.fakeClient.PatchDrive(ctx, id, patch)
}
