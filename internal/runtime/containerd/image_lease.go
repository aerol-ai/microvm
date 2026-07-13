package containerd

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/leases"
)

const (
	imageLeaseLabelKey = "aerolvm.image_lease"
	leaseContentType   = "content"
	// leaseExpiry is a GC backstop: the driver releases image leases explicitly
	// on every success (Destroy) and failure path, but a daemon crash between
	// pinning and NewContainer leaves an orphan with no defer to run and no
	// lease reconciler. An expiration lets containerd GC reclaim such orphans.
	// It never threatens a live sandbox: once NewContainer returns, the
	// container's own snapshot pins the layers independently of this lease.
	leaseExpiry = 24 * time.Hour
)

// leaseManager is the containerd leases.Manager surface pin/release need.
// Tests inject a fake so the lease path is covered offline.
type leaseManager interface {
	Create(context.Context, ...leases.Opt) (leases.Lease, error)
	Delete(context.Context, leases.Lease, ...leases.DeleteOpt) error
	AddResource(context.Context, leases.Lease, leases.Resource) error
}

// leasesServiceFn resolves the lease manager. Production uses client.Raw();
// tests override.
var leasesServiceFn = func(client *Client) leaseManager {
	if client == nil {
		return nil
	}
	raw := client.Raw()
	if raw == nil {
		return nil
	}
	return raw.LeasesService()
}

// pinImageLease creates a containerd lease pinning image content so GC cannot
// reap layers mid-create (Phase 3). No-op when the client has no lease service.
func (d *Driver) pinImageLease(ctx context.Context, client *Client, image cntr.Image) (string, error) {
	_ = d
	if client == nil || image == nil {
		return "", nil
	}
	ls := leasesServiceFn(client)
	if ls == nil {
		return "", nil
	}
	leaseID, err := randomLeaseID("aerolvm-img-")
	if err != nil {
		return "", err
	}
	lease, err := ls.Create(ctx, leases.WithID(leaseID), leases.WithExpiration(leaseExpiry))
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
	ls := leasesServiceFn(client)
	if ls == nil {
		return
	}
	_ = ls.Delete(ctx, leases.Lease{ID: leaseID})
}

func randomLeaseID(prefix string) (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(b), nil
}
