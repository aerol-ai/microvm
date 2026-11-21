package procgroup

import (
	"context"
	"os/exec"
	"runtime"
	"testing"
)

func TestRunRunsTheCommand(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX commands")
	}
	if err := Run(context.Background(), exec.CommandContext(context.Background(), "true")); err != nil {
		t.Fatal(err)
	}
}
