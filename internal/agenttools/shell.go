package agenttools

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// DefaultShellSession is the session a shell opens when none is named. The
// SSH gateway attaches `ssh <id>@host` to the same name
// (pkg/sshgateway/gateway.go parseSSHUser), so both land in one shell.
const DefaultShellSession = "default"

// ShellRequest opens an interactive login shell in a sandbox.
type ShellRequest struct {
	// Name is the session to attach to. Empty means DefaultShellSession.
	Name string
	// Term is the TERM a new shell starts with.
	Term string
	// Cols and Rows size a new shell's PTY.
	Cols, Rows int
}

// Shell is the session a ShellRequest landed in.
type Shell struct {
	Session models.Session
	// Created is false when a running shell with the name was reused.
	Created bool
}

// OpenShell returns the running PTY session named req.Name, or starts a
// login shell under that name (toolboxd's default for a session with no
// command: bash -l, falling back to sh). Sessions outlive their connection,
// so a closed terminal or a dropped network leaves the shell running, and
// the next OpenShell with the same name lands back in it.
//
// toolboxd's POST /sessions always creates a new session, so this is
// list-then-create, like the SSH gateway's findOrCreateSession. Two first
// opens racing can each create one; both get a working shell, and later
// opens pick the newest, which is also the one toolboxd's name index holds.
func (t *Tools) OpenShell(ctx context.Context, sb *microvm.Sandbox, req ShellRequest) (Shell, error) {
	if err := RequireShell(sb); err != nil {
		return Shell{}, err
	}
	// Buffered exec is WASM's only exec path (eng review D10); it has no
	// PTY to give a shell.
	if IsWasm(sb) {
		return Shell{}, &Error{
			Code:    CodeUnsupportedRuntime,
			Message: "WASM sandboxes have no interactive shell",
			Hint:    "run commands with exec instead",
		}
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = DefaultShellSession
	}
	sessions, err := sb.ListSessions(ctx)
	if err != nil {
		return Shell{}, Classify(err)
	}
	var found *models.Session
	for i, s := range sessions {
		// A non-PTY session with the name (a command started through the
		// Daytona facade, say) is not a shell to type into.
		if s.Name != name || !s.PTY || s.Status != models.SessionStatusRunning {
			continue
		}
		if found == nil || s.CreatedAt.After(found.CreatedAt) {
			found = &sessions[i]
		}
	}
	if found != nil {
		return Shell{Session: *found}, nil
	}
	var env map[string]string
	if req.Term != "" {
		env = map[string]string{"TERM": req.Term}
	}
	created, err := sb.CreateSession(ctx, sdktypes.CreateSessionOptions{
		Name: name, PTY: true, Cols: req.Cols, Rows: req.Rows, Env: env,
	})
	if err != nil {
		return Shell{}, Classify(err)
	}
	return Shell{Session: created, Created: true}, nil
}

// NewShellName returns a session name no other shell uses, for a shell of
// its own instead of the shared default.
func NewShellName() (string, error) {
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "shell-" + hex.EncodeToString(buf), nil
}

// ExitStatus is the exit code a finished command reports: 128+n when a
// known signal ended it, like a shell or `docker exec`, else its own code.
func ExitStatus(code int, signal string) int {
	if n := signalExitCode(signal); n != 0 {
		return n
	}
	return code
}
