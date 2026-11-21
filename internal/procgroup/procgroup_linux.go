//go:build linux

package procgroup

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func run(ctx context.Context, cmd *exec.Cmd) error {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	if err := cmd.Start(); err != nil {
		return err
	}
	pgid := cmd.Process.Pid
	// The group, not only the child exec.CommandContext would kill. The
	// leader is not reaped until Wait, so its pid, the group's id, is
	// not reused while this can fire.
	stop := context.AfterFunc(ctx, func() { _ = killGroup(pgid) })
	err := cmd.Wait()
	stop()
	// Whatever the child left behind goes with it. Its group keeps the id
	// in use while any member is left, so this reaches only them.
	_ = killGroup(pgid)
	waitGone(pgid)
	return err
}

// killGroup sends SIGKILL to every member of the group; a group with none
// left is no error.
func killGroup(pgid int) error {
	if err := syscall.Kill(-pgid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}

// waitGone waits until no member of the group runs, for at most GoneWait.
func waitGone(pgid int) {
	for end := time.Now().Add(GoneWait); groupRuns(pgid) && time.Now().Before(end); {
		time.Sleep(2 * time.Millisecond)
	}
}

// groupRuns reports whether a member of the group still runs. A killed
// member whose parent has not reaped it yet stays in the group as a
// zombie, which runs no more of its code; an orphan's new parent (init,
// or a container's first process) reaps it when it gets to it.
func groupRuns(pgid int) bool {
	if errors.Is(syscall.Kill(-pgid, 0), syscall.ESRCH) {
		return false
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return true
	}
	for _, e := range entries {
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		raw, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue
		}
		// pid (comm) state ppid pgrp ...: comm may hold anything, so
		// the fields are read after its last ')'.
		s := string(raw)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) < 3 || f[0] == "Z" || f[0] == "X" {
			continue
		}
		if g, err := strconv.Atoi(f[2]); err == nil && g == pgid {
			return true
		}
	}
	return false
}
