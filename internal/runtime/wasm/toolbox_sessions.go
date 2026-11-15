package wasm

import (
	"context"

	"github.com/aerol-ai/microvm/internal/runtime/wasm/toolhost"
	"github.com/aerol-ai/microvm/internal/toolboxwire"
)

// sandboxSessions gives the per-request toolhost the sandbox's sessions,
// which live on the driver (sandboxInstance.sessions): the toolhost is
// rebuilt for every request, a session outlives them all.
type sandboxSessions struct {
	driver *Driver
	id     string
}

func (s sandboxSessions) Create(id string) (bool, error) {
	set, err := s.driver.sessionsFor(s.id)
	if err != nil {
		return false, err
	}
	return set.create(id)
}

func (s sandboxSessions) List() []toolhost.SessionInfo {
	set, err := s.driver.sessionsFor(s.id)
	if err != nil {
		return nil
	}
	return set.list()
}

func (s sandboxSessions) Get(id string) (toolhost.SessionInfo, error) {
	set, err := s.driver.sessionsFor(s.id)
	if err != nil {
		return toolhost.SessionInfo{}, err
	}
	return set.get(id)
}

func (s sandboxSessions) Delete(id string) error {
	set, err := s.driver.sessionsFor(s.id)
	if err != nil {
		return err
	}
	return set.delete(id)
}

func (s sandboxSessions) Exec(ctx context.Context, sessionID string, cmd toolhost.SessionCommand, async bool) (toolhost.CommandResult, error) {
	set, err := s.driver.sessionsFor(s.id)
	if err != nil {
		return toolhost.CommandResult{}, err
	}
	return set.exec(ctx, sessionID, cmd, async)
}

func (s sandboxSessions) Command(sessionID, commandID string) (toolhost.CommandInfo, error) {
	set, err := s.driver.sessionsFor(s.id)
	if err != nil {
		return toolhost.CommandInfo{}, err
	}
	return set.command(sessionID, commandID)
}

func (s sandboxSessions) Logs(sessionID, commandID string, q toolboxwire.LogQuery) (toolboxwire.LogWindow, toolboxwire.LogWindow, error) {
	set, err := s.driver.sessionsFor(s.id)
	if err != nil {
		return toolboxwire.LogWindow{}, toolboxwire.LogWindow{}, err
	}
	return set.logs(sessionID, commandID, q)
}

func (s sandboxSessions) Follow(sessionID, commandID string) (*toolhost.LogFollow, error) {
	set, err := s.driver.sessionsFor(s.id)
	if err != nil {
		return nil, err
	}
	return set.follow(sessionID, commandID)
}

func (s sandboxSessions) Input(ctx context.Context, sessionID, commandID string, data []byte) error {
	set, err := s.driver.sessionsFor(s.id)
	if err != nil {
		return err
	}
	return set.input(ctx, sessionID, commandID, data)
}

func (s sandboxSessions) Entrypoint(ctx context.Context, logs bool) (toolhost.EntrypointInfo, error) {
	return s.driver.entrypoint(ctx, s.id, logs)
}

func (s sandboxSessions) FollowEntrypoint(ctx context.Context) (*toolhost.LogFollow, error) {
	return s.driver.followEntrypoint(ctx, s.id)
}
