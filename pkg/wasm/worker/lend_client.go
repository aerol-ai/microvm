package worker

import (
	"context"
	"errors"
	"fmt"
	"time"

	wasmengine "github.com/aerol-ai/microvm/pkg/wasm"
)

// sandboxd's half of lent folders (lend.go): a message whose caps name a
// lent folder (wasmengine.Preopen.Lent) goes without it, and the helper is
// asked to lend it (GrantPolicy.Lend).

// lendTimeout bounds one loan sandboxd asks the helper for.
const lendTimeout = 10 * time.Second

// lentGrants is paths without the folders the helper lends, and the policy
// to lend them with: nil when caps names none.
func lentGrants(caps wasmengine.Capabilities, paths []string) ([]string, *GrantPolicy) {
	lent := false
	for _, p := range caps.Preopens {
		lent = lent || p.Lent
	}
	if !lent {
		return paths, nil
	}
	skip := map[string]bool{}
	for _, p := range caps.Preopens {
		if p.Lent {
			skip[p.HostPath] = true
		}
	}
	own := make([]string, 0, len(paths))
	for _, path := range paths {
		if !skip[path] {
			own = append(own, path)
		}
	}
	p := grantPolicy.Load()
	if p == nil {
		p = &GrantPolicy{}
	}
	return own, p
}

// errNoLender fails a message naming folders the helper lends when no
// helper lends them (GrantPolicy.Lend is unset).
var errNoLender = errors.New("this sandbox's mounts are the root helper's to lend, and no helper lends them")

// lend has the helper lend sandboxID's folders to the worker c dials. p is
// lentGrants' answer: nil, there is nothing to lend.
func (c *Client) lend(ctx context.Context, p *GrantPolicy, sandboxID string) error {
	if p == nil {
		return nil
	}
	if p.Lend == nil {
		return errNoLender
	}
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, lendTimeout)
	defer cancel()
	if err := p.Lend(ctx, sandboxID, c.socketPath); err != nil {
		return fmt.Errorf("lend sandbox %s's mounts to its WASM host: %w", sandboxID, err)
	}
	return nil
}
