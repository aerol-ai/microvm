//go:build !linux

package procgroup

import (
	"context"
	"os/exec"
)

func run(_ context.Context, cmd *exec.Cmd) error { return cmd.Run() }
