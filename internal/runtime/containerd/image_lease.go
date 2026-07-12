package containerd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/leases"
)

const (
	imageLeaseLabelKey = "aerolvm.image_lease"
	leaseContentType   = "content"
)

// pinImageLease creates a containerd lease pinning image content so GC cannot
// reap layers mid-create (Phase 3). No-op when the client has no live backend.
func (d *Driver) pinImageLease(ctx context.Context, client *Client, image cntr.Image) (string, error) {
	_ = d
	if client == nil || image == nil {
		return "", nil
	}
	raw := client.Raw()
	if raw == nil {
		return "", nil
	}
	leaseID, err := randomLeaseID("aerolvm-img-")
	if err != nil {
		return "", err
	}
	ls := raw.LeasesService()
	lease, err := ls.Create(ctx, leases.WithID(leaseID))
	if err != nil {
		return "", fmt.Errorf("create image lease: %w", err)
	}
	digest := strings.TrimSpace(image.Target().Digest.String())
	if digest == "" {
		_ = ls.Delete(ctx, lease)
		return "", errors.New("image has no content digest")
	}
	if err := ls.AddResource(ctx, lease, leases.Resource{ID: digest, Type: leaseContentType}); err != nil {
		_ = ls.Delete(ctx, lease)
		return "", fmt.Errorf("pin image lease: %w", err)
	}
	return lease.ID, nil
}

func (d *Driver) releaseImageLease(ctx context.Context, client *Client, labels map[string]string) {
	if client == nil || labels == nil {
		return
	}
	leaseID := strings.TrimSpace(labels[imageLeaseLabelKey])
	if leaseID == "" {
		return
	}
	raw := client.Raw()
	if raw == nil {
		return
	}
	_ = raw.LeasesService().Delete(ctx, leases.Lease{ID: leaseID})
}

func randomLeaseID(prefix string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}
