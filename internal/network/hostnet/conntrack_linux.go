//go:build linux

package hostnet

import (
	"context"
	"os/exec"
	"strings"

	"github.com/aerol-ai/microvm/internal/procgroup"
)

// execConntrack is a test seam over the conntrack CLI.
var execConntrack = func(args ...string) error {
	cmd := exec.Command("conntrack", args...)
	return cmd.Run()
}

// execConntrackContext is the root helper's: the run ends with ctx, and
// takes any child it started with it. A test seam too.
var execConntrackContext = func(ctx context.Context, args ...string) error {
	return procgroup.Run(ctx, exec.CommandContext(ctx, "conntrack", args...))
}

func flushConntrackContext(ctx context.Context, ip string) error {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return nil
	}
	// Both directions, as runConntrackDelete; no run starts once ctx ended.
	for _, dir := range []string{"-s", "-d"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		_ = execConntrackContext(ctx, "-D", dir, ip)
	}
	return ctx.Err()
}
