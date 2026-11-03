package firecracker

import (
	"context"
	"fmt"

	dockerpkg "github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ConfigureAOCRPullAuth installs the node-local cluster PAT a cold-boot pull
// of an in-scope AOCR `cluster/` ref presents, with the same signature and
// no-op rules as the container engines' (docker.Client and the containerd
// driver). A snapshot another node pushed lives there.
func (d *Driver) ConfigureAOCRPullAuth(hosts []string, clusterID, patPath string) {
	if a := dockerpkg.NewAOCRPullAuth(hosts, clusterID, patPath); a != nil {
		d.aocrPullAuth = a
	}
}

// rootfsSource picks where a cold boot reads image from, and with which
// credential.
//
//   - A snapshot image this node holds (the aerolvm-snapshot/ namespace) is
//     read from the node's image store: it may never have been pushed, and
//     when it was, the local copy is the same image without a download. One
//     this node no longer holds is pulled from its pushed copy, registryRef,
//     when the request carries one; its local tag means nothing to a registry.
//   - Anything else is pulled from its registry, with the request's own
//     credential, or for an in-scope AOCR ref with none, the cluster PAT;
//     the same rule as the containerd driver's pullAuthFor. A snapshot
//     another node pushed arrives here as its AOCR ref.
//
// cleanup releases whatever the source staged; it is never nil.
func (d *Driver) rootfsSource(ctx context.Context, image, registryRef string, registry *models.RegistryAuth) (source string, auth *models.RegistryAuth, cleanup func(), err error) {
	cleanup = func() {}
	if dockerpkg.IsSnapshotImageRef(image) {
		if d.images != nil {
			src, release, ok, err := d.images.OpenImage(ctx, image)
			if err != nil {
				return "", nil, cleanup, fmt.Errorf("open snapshot image %s: %w", image, err)
			}
			if ok {
				if release == nil {
					release = func() {}
				}
				return src, nil, release, nil
			}
		}
		if registryRef != "" {
			image = registryRef
		}
	}
	if registry != nil && registry.Username != "" {
		return ociImageRefFor(image), registry, cleanup, nil
	}
	aocr, err := d.aocrPullAuth.Resolve(image)
	if err != nil {
		// Same policy as both container engines: warn and try anonymously;
		// a private ref then fails at the pull with the registry's answer.
		d.logger.Warn("firecracker create: cluster registry PAT unreadable; pulling anonymously",
			"image", image, "error", err)
		aocr = nil
	}
	return ociImageRefFor(image), aocr, cleanup, nil
}
