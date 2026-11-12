package docker

import "context"

// PrepareImage pulls imageRef ahead of a create unless it is already here,
// for a decommission move (C9). A local image (a committed snapshot) is
// never pulled.
func (c *Client) PrepareImage(ctx context.Context, imageRef string) error {
	if ok, err := c.ImageExists(ctx, imageRef); err == nil && ok {
		return nil
	}
	return c.PullImage(ctx, imageRef, nil)
}
