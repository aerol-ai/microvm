package nodeupgrade

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"time"
)

// LaunchUnit is the transient systemd unit an operation runs in.
func LaunchUnit(op string) string { return "aerolvm-upgrade-" + op }

// Launch starts `<binary> upgrade node …` for req in a transient systemd
// unit of its own, aerolvm-upgrade-<op>, and returns the op ID without
// waiting for it. The routes that start an upgrade use it (Phase 3b): run
// from inside sandboxd, the upgrader would sit in sandboxd's cgroup and
// die when it stops sandboxd (KillMode=control-group). Every value is a
// separate argument to systemd-run; nothing goes through a shell.
func Launch(ctx context.Context, host Host, binary string, req Request) (string, error) {
	if req.Op == "" {
		req.Op = NewOpID(time.Now())
	}
	if _, err := req.validate(runtime.GOOS, runtime.GOARCH); err != nil {
		return "", err
	}
	if !strings.HasPrefix(binary, "/") {
		return "", fmt.Errorf("launch needs the absolute path of sandboxd, got %q", binary)
	}
	args := []string{
		"--unit=" + LaunchUnit(req.Op),
		"--description=AerolVM node upgrade " + req.Op,
		"--collect",
		"--quiet",
		"--",
		binary,
	}
	args = append(args, req.Args()...)
	if out, err := host.Run(ctx, "systemd-run", args...); err != nil {
		return "", fmt.Errorf("systemd-run %s: %w: %s", LaunchUnit(req.Op), err, tail(out))
	}
	return req.Op, nil
}
