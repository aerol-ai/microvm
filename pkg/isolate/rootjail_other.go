//go:build !linux

package isolate

import (
	"errors"
	"os/exec"
)

func mountJailTmpfs(string, int, int, uint32) error {
	return errors.New("isolate jail: tmpfs mounts need Linux")
}

func mounted(string) bool { return false }

func setJailProcAttr(*exec.Cmd) {}
