// Package runscwrap is aerolvm-runsc, the runsc the gVisor containerd shim
// runs for a sandbox that moved to this worker with its memory (C21,
// plans/kubernetes-v2-architecture.md §10.5).
//
// The stock shim (containerd-shim-runsc-v1) answers a task checkpoint with
// "not implemented" and restores only through an extension GKE links into
// its own build. It does run whatever binary its options name
// (binary_name), from the container's bundle directory. So the containerd
// driver creates a moved sandbox's container with that option pointing
// here and RestoreAnnotation on its spec naming the staged checkpoint, and
// the shim's "start" of it becomes runsc's "restore" of the created
// container. runsc restores into a created container (it loads it and
// skips the create), and the shim sees a start that succeeded: its wait,
// state, exec and kill run on as for any task. Every other call, and a
// start whose checkpoint is gone (a later restart of the same container),
// goes to runsc unchanged.
package runscwrap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

const (
	// CommandName is the name the supervisor answers to as this wrapper.
	CommandName = "aerolvm-runsc"
	// RestoreAnnotation names the directory of a checkpoint to restore the
	// container from.
	RestoreAnnotation = "io.aerolvm.restore-image-path"
	// CheckpointFile is the file runsc writes first in a checkpoint
	// directory: a directory without it holds no checkpoint.
	CheckpointFile = "checkpoint.img"
	// specFile is the OCI spec in the bundle, the shim's working directory.
	specFile = "config.json"
)

// Args is the runsc argument list for the shim's args: runsc's own flags
// (always --name=value from the shim), then the command and its operands.
// A "start <id>" of a container whose spec names a directory holding a
// checkpoint becomes "restore --image-path=<dir> --detach <id>"; anything
// else is args unchanged.
func Args(args []string, spec []byte, hasCheckpoint func(dir string) bool) []string {
	n := len(args)
	if n < 2 || args[n-2] != "start" || strings.HasPrefix(args[n-1], "-") {
		return args
	}
	for _, a := range args[:n-2] {
		if !strings.HasPrefix(a, "-") {
			// An operand before "start": not the shim's start.
			return args
		}
	}
	dir := restoreDir(spec)
	if dir == "" || !hasCheckpoint(dir) {
		return args
	}
	out := make([]string, 0, n+2)
	out = append(out, args[:n-2]...)
	return append(out, "restore", "--image-path="+dir, "--detach", args[n-1])
}

func restoreDir(spec []byte) string {
	var s struct {
		Annotations map[string]string `json:"annotations"`
	}
	if len(spec) == 0 || json.Unmarshal(spec, &s) != nil {
		return ""
	}
	// Our driver writes a clean absolute path; anything else is refused
	// (the ".." test is also the one code scanning recognizes).
	raw := strings.TrimSpace(s.Annotations[RestoreAnnotation])
	if raw == "" || strings.Contains(raw, "..") || !filepath.IsAbs(raw) {
		return ""
	}
	return filepath.Clean(raw)
}

// HasCheckpoint reports whether dir holds a checkpoint.
func HasCheckpoint(dir string) bool {
	fi, err := os.Stat(filepath.Join(dir, CheckpointFile))
	return err == nil && fi.Mode().IsRegular()
}

// runscPath is the runsc next to the wrapper, which the images install
// side by side, else the one on PATH.
func runscPath(self string) string {
	if p := filepath.Join(filepath.Dir(self), "runsc"); filepath.IsAbs(p) {
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
	}
	return "runsc"
}

// execFn is syscall.Exec; tests replace it.
var execFn = syscall.Exec

// lookPath resolves "runsc" on PATH; tests replace it.
var lookPath = func(name string) (string, error) {
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		p := filepath.Join(dir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode()&0o111 != 0 {
			return p, nil
		}
	}
	return "", os.ErrNotExist
}

// Main replaces this process with runsc, given the wrapper's own argv. It
// returns only when that fails, with the exit status to use.
func Main(argv []string) int {
	if len(argv) == 0 {
		return 2
	}
	spec, _ := os.ReadFile(specFile)
	args := Args(argv[1:], spec, HasCheckpoint)
	bin := runscPath(argv[0])
	if !filepath.IsAbs(bin) {
		p, err := lookPath(bin)
		if err != nil {
			os.Stderr.WriteString(CommandName + ": runsc not found\n")
			return 127
		}
		bin = p
	}
	err := execFn(bin, append([]string{bin}, args...), os.Environ())
	os.Stderr.WriteString(CommandName + ": exec " + bin + ": " + err.Error() + "\n")
	return 126
}
