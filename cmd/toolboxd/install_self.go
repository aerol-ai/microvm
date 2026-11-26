package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// selfExecutable finds the running binary; tests point it elsewhere.
var selfExecutable = os.Executable

// installSelf copies the running toolboxd to the one path in args. It is
// the whole job of a pod-mode sandbox's init container
// (internal/runtime/kubepod): that container runs
// "toolboxd --install-to /aerolvm/toolbox/toolboxd" from the toolbox image,
// and the sandbox container then runs the copy as PID 1 from a volume it
// mounts read-only. Copying itself means the toolbox image needs no shell
// and no cp: it can hold toolboxd alone.
//
// The copy goes to a temporary file next to the target and is renamed into
// place, so a half-written binary is never at the target path.
func installSelf(args []string) error {
	if len(args) != 1 || !filepath.IsAbs(args[0]) {
		return errors.New("usage: toolboxd --install-to <absolute path>")
	}
	dest := filepath.Clean(args[0])
	self, err := selfExecutable()
	if err != nil {
		return fmt.Errorf("find own binary: %w", err)
	}
	src, err := os.Open(self)
	if err != nil {
		return fmt.Errorf("open own binary: %w", err)
	}
	defer src.Close()
	tmp, err := os.CreateTemp(filepath.Dir(dest), ".toolboxd-*")
	if err != nil {
		return fmt.Errorf("install to %s: %w", dest, err)
	}
	// After the rename this removes nothing.
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, src); err != nil {
		tmp.Close()
		return fmt.Errorf("install to %s: %w", dest, err)
	}
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		return fmt.Errorf("install to %s: %w", dest, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("install to %s: %w", dest, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("install to %s: %w", dest, err)
	}
	if err := os.Rename(tmp.Name(), dest); err != nil {
		return fmt.Errorf("install to %s: %w", dest, err)
	}
	return nil
}
