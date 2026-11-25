package microvm

import (
	"context"

	sdktypes "github.com/aerol-ai/microvm/sdk/go/pkg/types"
)

// Runtimes tells a caller which runtimes this deployment offers and what
// each can do, so it can pick one for Create. Any credential that may read
// sandboxes may call it.
func (c *Client) Runtimes() *Runtimes {
	return &Runtimes{client: c}
}

// Runtimes is the runtime listing of a Client; get one from Client.Runtimes.
type Runtimes struct {
	client *Client
}

// List returns every runtime a create accepts, in the server's order, with
// its features, limits and whether any node offers it now (Available). It
// is a read and changes nothing, so it is safe to retry.
func (r *Runtimes) List(ctx context.Context) ([]sdktypes.RuntimeInfo, error) {
	return r.client.inner.ListRuntimes(ctx)
}
