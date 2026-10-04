package agenttools

import (
	"context"
	"strings"

	"github.com/aerol-ai/microvm/pkg/models"
	"github.com/aerol-ai/microvm/sdk/go/pkg/microvm"
)

// Resolve finds the sandbox a "<id-or-name>" reference names, with one
// request (eng review D12). A ref shaped like a generated ID ("sb-" plus 16
// hex) is looked up as an ID only; anything else as a name only. There is no
// fallback from one to the other, so a name can never shadow an ID, and
// creates reject names with the ID shape. Name lookups go through
// GetByName, which refuses a reply from a server that ignored ?name=
// (server_unsupported) rather than guessing from an unfiltered list.
func (t *Tools) Resolve(ctx context.Context, ref string) (*microvm.Sandbox, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, newError(CodeInvalidArgument, "a sandbox ID or name is required")
	}
	var (
		sb  *microvm.Sandbox
		err error
	)
	if models.IsGeneratedSandboxID(ref) {
		sb, err = t.client.Get(ctx, ref)
	} else {
		sb, err = t.client.GetByName(ctx, ref)
	}
	if err != nil {
		e := Classify(err)
		if e.Code == CodeNotFound {
			cp := *e
			cp.Message = "sandbox " + quote(ref) + " not found"
			return nil, &cp
		}
		return nil, e
	}
	return sb, nil
}

// RequireShell refuses runtimes that have no shell or filesystem, before any
// toolbox call, so the caller gets a clear reason instead of a raw 501
// (eng review D11).
func RequireShell(sb *microvm.Sandbox) error {
	if sb != nil && strings.TrimSpace(sb.Runtime) == models.RuntimeIsolate {
		return &Error{
			Code:    CodeUnsupportedRuntime,
			Message: "isolate sandboxes have no shell or filesystem; use the SDK's invoke",
		}
	}
	return nil
}

// EnsureStarted starts a stopped sandbox. Toolbox calls don't wake a stopped
// sandbox, and agent sandboxes are stopped after 30 minutes idle by default
// (eng review D7), so file and exec operations start it first.
func (t *Tools) EnsureStarted(ctx context.Context, sb *microvm.Sandbox) (*microvm.Sandbox, error) {
	if sb == nil || sb.Status != models.SandboxStatusStopped {
		return sb, nil
	}
	started, err := t.client.Start(ctx, sb.ID)
	if err != nil {
		return nil, Classify(err)
	}
	return started, nil
}

// Target resolves ref for an exec or file operation: resolve, refuse
// shell-less runtimes, and start the sandbox if it is stopped.
func (t *Tools) Target(ctx context.Context, ref string) (*microvm.Sandbox, error) {
	sb, err := t.Resolve(ctx, ref)
	if err != nil {
		return nil, err
	}
	if err := RequireShell(sb); err != nil {
		return nil, err
	}
	return t.EnsureStarted(ctx, sb)
}

func quote(s string) string { return "\"" + s + "\"" }
