package firecracker

import (
	"context"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestVMM_ExtraCoverage2(t *testing.T) {
	t.Run("ShutdownTimeoutEscalation", func(t *testing.T) {
		// Create a sleep process that ignores SIGTERM, forcing escalation to SIGKILL
		cmd := exec.Command("sh", "-c", "trap '' TERM; sleep 10")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Start()

		v := &vmm{
			cmd:     cmd,
			waitCh:  make(chan struct{}),
			started: true,
		}

		go func() {
			cmd.Wait()
			close(v.waitCh)
		}()

		// Call shutdown with a small grace period (1ms)
		err := v.Shutdown(context.Background(), 1*time.Millisecond)
		if err != nil {
			t.Errorf("Shutdown returned error: %v", err)
		}
	})

	t.Run("ShutdownContextCancel", func(t *testing.T) {
		cmd := exec.Command("sh", "-c", "trap '' TERM; sleep 10")
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Start()

		v := &vmm{
			cmd:     cmd,
			waitCh:  make(chan struct{}),
			started: true,
		}

		go func() {
			cmd.Wait()
			close(v.waitCh)
		}()

		ctx, cancel := context.WithCancel(context.Background())
		cancel() // immediately cancel

		// Should hit ctx.Done()
		err := v.Shutdown(ctx, 1*time.Minute)
		if err == nil || !strings.Contains(err.Error(), "context canceled") {
			t.Errorf("expected context canceled error, got %v", err)
		}

		// Cleanup the sleep process
		v.Kill()
	})

	t.Run("StderrTailNil", func(t *testing.T) {
		v := &vmm{}
		if v.StderrTail() != "" {
			t.Errorf("expected empty StderrTail, got %q", v.StderrTail())
		}
	})

	t.Run("CleanupRunDirEmpty", func(t *testing.T) {
		v := &vmm{}
		if err := v.Cleanup(); err != nil {
			t.Errorf("expected nil error, got %v", err)
		}
	})

	t.Run("CleanupPathInjection", func(t *testing.T) {
		v := &vmm{
			runDir: "/some/other/path/runDir",
			cfg: Config{
				RunDir: "/allowed/path",
			},
		}
		if err := v.Cleanup(); err == nil || !strings.Contains(err.Error(), "refusing to clean up path outside") {
			t.Errorf("expected path injection error, got %v", err)
		}
	})

}
