package microvm

import (
	"context"

	"github.com/aerol-ai/microvm/sdk/go/internal/apiclient"
	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// FeatureFilesWatch is the feature an *UnsupportedFeatureError names when a
// sandbox's agent predates file watching.
const FeatureFilesWatch = apiclient.FeatureFilesWatch

// WatchHandle is a running file watch.
type WatchHandle struct {
	inner *apiclient.WatchHandle
}

// WatchFiles streams changes under path in sandbox id: create, write,
// remove, rename and chmod events, plus overflow when events were lost.
// It returns once the watch is armed.
//
// Only gVisor and Firecracker sandboxes can watch; any other runtime answers
// an *APIError with status 501. A sandbox whose agent predates file watching
// answers an *UnsupportedFeatureError (errors.Is(err, ErrUnsupportedFeature)).
// The request is not retried: a watch is a stream.
func (c *Client) WatchFiles(ctx context.Context, id, path string, options sdktypes.WatchOptions) (*WatchHandle, error) {
	handle, err := c.inner.WatchFiles(ctx, id, path, options)
	if err != nil {
		return nil, err
	}
	return &WatchHandle{inner: handle}, nil
}

// WatchFiles streams changes under path in this sandbox. See Client.WatchFiles.
func (s *Sandbox) WatchFiles(ctx context.Context, path string, options sdktypes.WatchOptions) (*WatchHandle, error) {
	return s.client.WatchFiles(ctx, s.ID, path, options)
}

// Stop ends the watch; Wait then returns nil.
func (h *WatchHandle) Stop() error { return h.inner.Stop() }

// Wait blocks until the watch ends: nil after Stop, an error naming the
// reason when the agent ended it (the folder was removed or moved), or the
// error that dropped the connection.
func (h *WatchHandle) Wait() error { return h.inner.Wait() }

// Done is closed when the watch has ended.
func (h *WatchHandle) Done() <-chan struct{} { return h.inner.Done() }
