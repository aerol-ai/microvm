package containerd

import "context"

// PrepareImage pulls imageRef into this node's image store ahead of a
// create, for a decommission move (C9): the target pulls while the old copy
// still runs, so the moved sandbox starts without a pull. It is the create
// path's own lookup and pull (ensureImage), so local and registry refs,
// the pull dedup and the failure backoff all behave as they do on a create.
func (d *Driver) PrepareImage(ctx context.Context, imageRef string) error {
	client, err := d.ensureClient()
	if err != nil {
		return err
	}
	_, err = d.ensureImage(ctx, client, imageRef, nil)
	return err
}
