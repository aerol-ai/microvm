package service

import (
	"errors"
	"fmt"
	"strings"

	"github.com/distribution/reference"
	"github.com/opencontainers/go-digest"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// ErrImageDigest is a create whose image_digest cannot hold: not a digest,
// or a digest the image name already contradicts. The caller's mistake, so
// a 400.
var ErrImageDigest = errors.New("image_digest")

// pinImageDigest binds a create's image to its image_digest (#83). The
// digest used to be recorded and never checked, so a tag moved in the
// registry between the caller's choice and the pull started other content
// with the caller's digest still on the request. Now the image itself names
// the digest (`repo@sha256:...`), and every engine pulls by it: Docker,
// containerd and skopeo fetch that manifest and check its hash, and a local
// copy is found by that digest only. Nothing else has to remember to check.
//
// The digest comes from the caller, or from a pushed snapshot's row (the
// manifest digest its registry copy was pushed under), so a node that
// starts the registry copy, a failover recreate included, starts exactly
// what was pushed, not whatever the tag points at by then.
//
// The tag is dropped, not kept beside the digest: a pull by digest ignores
// it, skopeo refuses a name with both, and a create policy must judge the
// content, not a tag that no longer decides it. The caller's tagged name
// stays in ImageRegistryRef, which normalization fills before this runs.
//
// An image that lives only on this node is never pulled, so there is no
// registry manifest to pin it to, and the digest is not looked at: a build
// or a committed snapshot (by name), or any image the create marks
// local_only (a loaded image may carry a registry-looking name, and pinning
// it would send the runtime to that registry). A pushed snapshot's registry
// copy, when a node starts that copy, is a registry image and is pinned.
//
// In memory only, and a fixed point: an image already pinned to the same
// digest is left as it is, so running normalization twice changes nothing.
func pinImageDigest(req *models.CreateSandboxRequest) error {
	want := strings.TrimSpace(req.ImageDigest)
	if want == "" {
		return nil
	}
	image := strings.TrimSpace(req.Image)
	if image == "" || docker.IsLocalOnlyImageRef(image) || req.ImageDistributionMode == models.ImageDistributionLocalOnly {
		return nil
	}
	d, err := digest.Parse(want)
	if err != nil {
		return fmt.Errorf("%w: %q is not an image digest (sha256:<64 hex digits>): %v", ErrImageDigest, want, err)
	}
	req.ImageDigest = d.String()
	if docker.LooksLikeImageID(image) {
		return fmt.Errorf("%w: image %q is an image id; name the registry image the digest belongs to", ErrImageDigest, image)
	}
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return fmt.Errorf("%w: image %q is not a registry image name: %v", ErrImageDigest, image, err)
	}
	if pinned, ok := named.(reference.Digested); ok {
		if pinned.Digest() != d {
			return fmt.Errorf("%w: image %q names digest %s, but image_digest is %s", ErrImageDigest, image, pinned.Digest(), d)
		}
		return nil
	}
	pinned, err := reference.WithDigest(reference.TrimNamed(named), d)
	if err != nil {
		return fmt.Errorf("%w: pin image %q to %s: %v", ErrImageDigest, image, d, err)
	}
	req.Image = reference.FamiliarString(pinned)
	return nil
}
