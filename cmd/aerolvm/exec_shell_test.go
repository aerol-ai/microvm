package main

import (
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

// `exec -it <sandbox>` with nothing to run opens the sandbox's shell, as
// kubectl users expect; with a command it stays a terminal exec, and a flag
// that only means something for a command keeps the old usage error.
func TestExecItWithoutCommandOpensShell(t *testing.T) {
	h, keys, _, _ := shellHarness(t)
	h.fake.AddSandbox(models.Sandbox{Name: "box"})
	done := h.runAsync("exec", "-it", "box")
	typeKeys(t, keys, "exit 4\n")
	if code := h.wait(done); code != 4 || !strings.Contains(h.stderr.String(), "new shell in box") {
		t.Fatalf("exec -it box = %d %q", code, h.stderr.String())
	}
	if creates := h.sessionCreates(); len(creates) != 1 || creates[0].Name != "default" {
		t.Fatalf("exec -it opened %+v, want the default shell session", creates)
	}
	for _, args := range [][]string{
		{"exec", "-it", "box", "--cwd", "/app"},
		{"exec", "-i", "box"},
		{"exec", "-t", "box"},
		{"exec", "-it", "box", "--timeout", "1s"},
	} {
		if code := h.run(args...); code != execFailure || !strings.Contains(h.stderr.String(), "no command given after --") {
			t.Fatalf("%v = %d %q", args, code, h.stderr.String())
		}
	}
}
