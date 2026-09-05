//go:build !linux

package containerd

import (
	"context"
	"fmt"

	cntr "github.com/containerd/containerd/v2/client"
)

func containerIPv4FromTask(ctx context.Context, task cntr.Task) (string, error) {
	_ = ctx
	_ = task
	return "", fmt.Errorf("containerd runtime requires linux")
}
