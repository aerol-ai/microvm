package wasm

import (
	"fmt"
	"path/filepath"

	"github.com/aerol-ai/microvm/cmd/toolboxd/sessions"
)

func (d *Driver) sessionsFor(inst *sandboxInstance) (*sessions.Manager, error) {
	if inst == nil {
		return nil, fmt.Errorf("nil sandbox instance")
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if inst.sessions != nil {
		return inst.sessions, nil
	}
	recDir := filepath.Join(inst.workDir, ".aerol-sessions")
	mgr, err := sessions.New(d.logger, sessions.Config{
		SandboxID:    inst.sandboxID,
		RecordingDir: recDir,
	})
	if err != nil {
		return nil, err
	}
	inst.sessions = mgr
	return mgr, nil
}
