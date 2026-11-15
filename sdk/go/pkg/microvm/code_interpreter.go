package microvm

import (
	"context"

	apiclient "github.com/aerol-ai/microvm/sdk/go/internal/apiclient"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// FeatureCodeInterpreter is the feature an *UnsupportedFeatureError names
// when a sandbox's agent predates the code interpreter. Restart the sandbox,
// or re-create its Firecracker template, to get the current agent.
const FeatureCodeInterpreter = apiclient.FeatureCodeInterpreter

// CodeRunError is a run that did not end normally (timed out, refused by the
// agent, or cut off); its Execution holds the partial output. Use errors.As
// to read it.
type CodeRunError = apiclient.CodeRunError

// ErrCodeRunTimeout matches a *CodeRunError whose run hit its timeout.
var ErrCodeRunTimeout = apiclient.ErrCodeRunTimeout

// CreateCodeContext starts a new code interpreter context in a sandbox: an
// interpreter process that keeps its variables between runs. Every
// interpreter call needs a sandbox whose agent lists "code.interpreter";
// an older one fails with an *UnsupportedFeatureError. Not retried once
// sent: each call makes a new context.
func (c *Client) CreateCodeContext(ctx context.Context, sandboxID string, opts sdktypes.CodeContextOptions) (sdktypes.CodeContext, error) {
	return c.inner.CreateCodeContext(ctx, sandboxID, opts)
}

// ListCodeContexts lists a sandbox's code contexts (not the default one).
func (c *Client) ListCodeContexts(ctx context.Context, sandboxID string) ([]sdktypes.CodeContext, error) {
	return c.inner.ListCodeContexts(ctx, sandboxID)
}

// GetCodeContext reads one code context; an unknown id is ErrNotFound.
func (c *Client) GetCodeContext(ctx context.Context, sandboxID, contextID string) (sdktypes.CodeContext, error) {
	return c.inner.GetCodeContext(ctx, sandboxID, contextID)
}

// DeleteCodeContext stops a code context's process and forgets it; an
// unknown id is ErrNotFound.
func (c *Client) DeleteCodeContext(ctx context.Context, sandboxID, contextID string) error {
	return c.inner.DeleteCodeContext(ctx, sandboxID, contextID)
}

// RestartCodeContext restarts a code context: same id, variables wiped.
func (c *Client) RestartCodeContext(ctx context.Context, sandboxID, contextID string) (sdktypes.CodeContext, error) {
	return c.inner.RestartCodeContext(ctx, sandboxID, contextID)
}

// RunCode runs code in a code context of a sandbox and returns its output,
// rich results and any exception once the run ends. Cancelling ctx
// interrupts the run (Execution.Interrupted); a client disconnect alone
// would not stop it. A timed-out or cut-off run returns the partial
// Execution with a *CodeRunError. Runs are never retried.
func (c *Client) RunCode(ctx context.Context, sandboxID, code string, opts sdktypes.RunCodeOptions) (*sdktypes.Execution, error) {
	return c.inner.RunCode(ctx, sandboxID, code, opts)
}

// CreateCodeContext starts a new code context in this sandbox. See
// Client.CreateCodeContext.
func (s *Sandbox) CreateCodeContext(ctx context.Context, opts sdktypes.CodeContextOptions) (sdktypes.CodeContext, error) {
	return s.client.CreateCodeContext(ctx, s.ID, opts)
}

// ListCodeContexts lists this sandbox's code contexts.
func (s *Sandbox) ListCodeContexts(ctx context.Context) ([]sdktypes.CodeContext, error) {
	return s.client.ListCodeContexts(ctx, s.ID)
}

// GetCodeContext reads one of this sandbox's code contexts.
func (s *Sandbox) GetCodeContext(ctx context.Context, contextID string) (sdktypes.CodeContext, error) {
	return s.client.GetCodeContext(ctx, s.ID, contextID)
}

// DeleteCodeContext deletes one of this sandbox's code contexts.
func (s *Sandbox) DeleteCodeContext(ctx context.Context, contextID string) error {
	return s.client.DeleteCodeContext(ctx, s.ID, contextID)
}

// RestartCodeContext restarts one of this sandbox's code contexts.
func (s *Sandbox) RestartCodeContext(ctx context.Context, contextID string) (sdktypes.CodeContext, error) {
	return s.client.RestartCodeContext(ctx, s.ID, contextID)
}

// RunCode runs code in this sandbox. See Client.RunCode.
func (s *Sandbox) RunCode(ctx context.Context, code string, opts sdktypes.RunCodeOptions) (*sdktypes.Execution, error) {
	return s.client.RunCode(ctx, s.ID, code, opts)
}
