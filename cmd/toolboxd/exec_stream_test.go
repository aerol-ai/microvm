package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
)

func TestInterpretWaitResultTreatsWrappedECHILDAsSuccess(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{
			name: "direct syscall error",
			err:  &os.SyscallError{Syscall: "waitid", Err: syscall.ECHILD},
		},
		{
			name: "wrapped syscall error",
			err:  fmt.Errorf("wrapped: %w", &os.SyscallError{Syscall: "waitid", Err: syscall.ECHILD}),
		},
		{
			name: "wrapped sentinel",
			err:  fmt.Errorf("wrapped: %w", syscall.ECHILD),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			code, signal := interpretWaitResult(tc.err)
			if code != 0 || signal != "" {
				t.Fatalf("interpretWaitResult(%v) = (%d, %q), want (0, \"\")", tc.err, code, signal)
			}
		})
	}
}

func TestInterpretWaitResultPreservesExitCode(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 17")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected non-zero exit error")
	}

	code, signal := interpretWaitResult(err)
	if code != 17 || signal != "" {
		t.Fatalf("interpretWaitResult(%v) = (%d, %q), want (17, \"\")", err, code, signal)
	}
}

func TestInterpretWaitResultPreservesSignal(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "kill -TERM $$")
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected signal exit error")
	}

	code, signal := interpretWaitResult(err)
	if code != -1 || signal != syscall.SIGTERM.String() {
		t.Fatalf("interpretWaitResult(%v) = (%d, %q), want (-1, %q)", err, code, signal, syscall.SIGTERM.String())
	}
}
