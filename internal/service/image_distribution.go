package service

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/aerol-ai/microvm/internal/store"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

const defaultAOCRRegistryHost = "aocr.aerol.ai"

// ImageDistributionProvider is the control-plane contract for image
// availability. Providers may verify digests or talk to an external registry
// cache, but the core daemon only needs the resulting placement metadata.
type ImageDistributionProvider interface {
	ClassifyImage(ctx context.Context, image string) (models.ImageDistributionMetadata, error)
}

type defaultImageDistributionProvider struct {
	aocrHost string
}

func newDefaultImageDistributionProvider(aocrHost string) ImageDistributionProvider {
	aocrHost = strings.ToLower(strings.TrimSpace(aocrHost))
	if aocrHost == "" {
		aocrHost = defaultAOCRRegistryHost
	}
	return defaultImageDistributionProvider{aocrHost: aocrHost}
}

func (p defaultImageDistributionProvider) ClassifyImage(_ context.Context, image string) (models.ImageDistributionMetadata, error) {
	image = strings.TrimSpace(image)
	if image == "" {
		return models.ImageDistributionMetadata{}, nil
	}
	if docker.IsLocalOnlyImageRef(image) {
		return models.ImageDistributionMetadata{
			Mode: models.ImageDistributionLocalOnly,
		}, nil
	}
	if host := imageRegistryHost(image); host != "" && host == p.aocrHost {
		return models.ImageDistributionMetadata{
			Mode:        models.ImageDistributionAOCR,
			RegistryRef: image,
		}, nil
	}
	return models.ImageDistributionMetadata{
		Mode:        models.ImageDistributionExternalRegistry,
		RegistryRef: image,
	}, nil
}

// authorizeTenantImageRef refuses the reference forms a user token could use
// to reach a snapshot it does not own without naming it:
//
//   - an image id, which the engine resolves by content (a short prefix is
//     enough), so it reaches any image on the node whatever its name;
//   - a ref into the cluster's snapshot registry outside the caller's own
//     namespace: the cluster's pull credential would fetch another
//     tenant's snapshot, or an operator one, for anyone who could spell it;
//   - a built image under another owner's namespace (Service.BuildImage
//     tags a tenant's builds with its own).
//
// Both read as not found, the answer a cross-tenant snapshot name gets. The
// equivalent spellings of a snapshot's name are covered by the lookup itself
// (docker.EquivalentImageNames). Operator and internal callers are not
// checked: they may start any image.
func authorizeTenantImageRef(owner string, refs ...string) error {
	for _, ref := range refs {
		ref = strings.TrimSpace(ref)
		if ref == "" {
			continue
		}
		if docker.LooksLikeImageID(ref) {
			return fmt.Errorf("%w: image %q (start a snapshot by its name)", store.ErrNotFound, ref)
		}
		if namespace, ok := snapshotRefNamespace(ref); ok && namespace != snapshotOwnerNamespace(owner) {
			return fmt.Errorf("%w: image %q", store.ErrNotFound, ref)
		}
		if docker.IsBuiltImageRef(ref) {
			if namespace := docker.BuiltImageOwnerNamespace(ref); namespace != "" && namespace != snapshotOwnerNamespace(owner) {
				return fmt.Errorf("%w: image %q", store.ErrNotFound, ref)
			}
		}
	}
	return nil
}

// maxSnapshotChain bounds how many snapshots one image reference may pass
// through. A registered snapshot's image may be another snapshot's name;
// eight hops is far past any real use, and the bound ends a loop.
const maxSnapshotChain = 8

// errSnapshotChain is a snapshot whose image names lead back to itself or
// through more than maxSnapshotChain snapshots. Nothing could start it.
var errSnapshotChain = errors.New("snapshot image chain loops or is too long")

// resolveSnapshotChain follows image through the snapshot catalog to the
// image the runtime would start. A name that is a snapshot's, in any
// spelling the engine treats as the same image, resolves to that snapshot's
// image, and that image may in turn be another snapshot's name. Every
// snapshot on the way must be visible to the caller, and for a user token
// every image on the way passes authorizeTenantImageRef. So the artifact
// that would run is authorized, not just the name the caller wrote, however
// many registered names lead to it.
//
// A snapshot's committed image (docker.SnapshotImageTag) named directly is
// reachable only through the snapshot it was committed for. Another
// account's snapshot with the caller's name does not stand in the way: its
// image lives under its own tag, so to this caller the name is an ordinary
// image. Only a snapshot committed before snapshots had tags of their own
// holds the name's tag itself, and that one still answers not found.
//
// It returns the last snapshot reached (nil when image names none) and the
// image to start. A catalog that cannot be read is an error, never "no
// snapshot": a failed lookup must not let a private snapshot's name pass as
// a plain image. stop is a snapshot name the chain must not reach — the one
// being registered — so registration cannot close a loop.
func (s *Service) resolveSnapshotChain(ctx context.Context, image, stop string) (*models.SandboxSnapshot, string, error) {
	owner, scoped := ownerScope(ctx)
	image = strings.TrimSpace(image)
	stopNames := map[string]bool{}
	if stop = strings.TrimSpace(stop); stop != "" {
		for _, name := range docker.EquivalentImageNames(stop) {
			stopNames[name] = true
		}
	}
	var last *models.SandboxSnapshot
	for hops := 0; ; hops++ {
		if scoped {
			if err := authorizeTenantImageRef(owner, image); err != nil {
				return nil, "", err
			}
		}
		names := docker.EquivalentImageNames(image)
		for _, name := range names {
			if stopNames[name] {
				return nil, "", fmt.Errorf("%w: %q leads back to %q", errSnapshotChain, image, stop)
			}
		}
		if scoped && docker.IsBuiltImageRef(image) && docker.BuiltImageOwnerNamespace(image) == "" {
			// A build with no owner in its tag — an operator's, or one
			// made before builds had owners — is anyone's who can guess its
			// Dockerfile, so a user token reaches it only through a
			// snapshot it can see that holds it.
			holders, err := s.store.GetSnapshotsByImage(ctx, names)
			if err != nil {
				return nil, "", err
			}
			if !slices.ContainsFunc(holders, func(holder *models.SandboxSnapshot) bool { return snapshotVisible(ctx, holder) }) {
				return nil, "", fmt.Errorf("%w: image %q", store.ErrNotFound, image)
			}
		}
		if docker.IsSnapshotImageRef(image) {
			snapshot, err := s.snapshotCommittedAs(ctx, names)
			switch {
			case err != nil:
				return nil, "", err
			case snapshot != nil && snapshotVisible(ctx, snapshot):
				return snapshot, snapshot.Image, nil
			case scoped:
				return nil, "", fmt.Errorf("%w: image %q", store.ErrNotFound, image)
			}
			return last, image, nil
		}
		snapshot, err := s.store.GetSnapshotByNames(ctx, names)
		if errors.Is(err, store.ErrNotFound) {
			return last, image, nil
		}
		if err != nil {
			return nil, "", err
		}
		if !snapshotVisible(ctx, snapshot) {
			if snapshot.SourceSandboxID != "" && slices.Contains(names, strings.TrimSpace(snapshot.Image)) {
				return nil, "", fmt.Errorf("%w: image %q", store.ErrNotFound, image)
			}
			return last, image, nil
		}
		if hops == maxSnapshotChain {
			return nil, "", fmt.Errorf("%w: %q", errSnapshotChain, image)
		}
		last = snapshot
		next := strings.TrimSpace(snapshot.Image)
		if next == "" || slices.Contains(docker.EquivalentImageNames(snapshot.Name), next) {
			// A snapshot committed before snapshots had tags of their
			// own, or one registered under its image's own name.
			if next == "" {
				next = image
			}
			return last, next, nil
		}
		image = next
	}
}

// snapshotCommittedAs returns the snapshot whose committed image is any of
// images (spellings of one docker.SnapshotImageTag), or nil. A tag is
// derived from one snapshot's name, so it has exactly one such snapshot;
// other rows naming the same image are registered aliases, which never
// authorize it.
func (s *Service) snapshotCommittedAs(ctx context.Context, images []string) (*models.SandboxSnapshot, error) {
	holders, err := s.store.GetSnapshotsByImage(ctx, images)
	if err != nil {
		return nil, err
	}
	for _, snapshot := range holders {
		if strings.TrimSpace(snapshot.Image) == docker.SnapshotImageTag(snapshot.Name) {
			return snapshot, nil
		}
	}
	return nil, nil
}

// NormalizeCreateImageDistribution resolves snapshot aliases and fills the
// create request's image-distribution metadata before placement decisions are
// made. The method is intentionally side-effect free: it does not pull, push,
// or verify image contents. Its result is a fixed point: a request it has
// already resolved resolves to itself, so callers that run it twice get the
// same answer and the same authorization.
func (s *Service) NormalizeCreateImageDistribution(ctx context.Context, req *models.CreateSandboxRequest) error {
	if req == nil {
		return nil
	}
	req.Image = strings.TrimSpace(req.Image)

	if s != nil && s.store != nil && req.Image != "" {
		owner, scoped := ownerScope(ctx)
		if scoped {
			if err := authorizeTenantImageRef(owner, req.ImageRegistryRef); err != nil {
				return err
			}
		}
		// A snapshot with no owner (registered by an operator, or older
		// than ownership with its source already gone) is the operator's:
		// nothing records which tenant, if any, may use it.
		var snapshot *models.SandboxSnapshot
		image := req.Image
		var err error
		dist := req.ImageDistribution()
		pushed := dist.Mode == models.ImageDistributionAOCR && dist.RegistryRef != ""
		fromRegistry := false
		switch {
		case docker.IsSnapshotImageRef(req.Image):
			// A snapshot's committed image, named by its tag. The tag
			// names one snapshot only, so the snapshot is found by that
			// image, and the caller must be able to see it. A node that
			// does not hold the snapshot starts a pushed snapshot's
			// registry copy (the create was placed or failed over here);
			// a user token's registry ref was checked against its own
			// namespace above.
			snapshot, err = s.snapshotCommittedAs(ctx, docker.EquivalentImageNames(req.Image))
			switch {
			case err != nil:
			case snapshot != nil && !snapshotVisible(ctx, snapshot):
				err = fmt.Errorf("%w: image %q", store.ErrNotFound, req.Image)
			case snapshot != nil:
				image = snapshot.Image
			case pushed:
				fromRegistry = true
			case scoped:
				err = fmt.Errorf("%w: image %q", store.ErrNotFound, req.Image)
			}
		case !isStoredSpecReplay(ctx):
			// A failover recreate replays an image its first create
			// already resolved, so names are not looked up again: on this
			// node a name may belong to a snapshot the sandbox never asked
			// for.
			snapshot, image, err = s.resolveSnapshotChain(ctx, req.Image, "")
		}
		switch {
		case err != nil:
			return err
		case fromRegistry:
			req.Image = dist.RegistryRef
		case snapshot != nil:
			// The last snapshot in the chain is the one whose image runs,
			// so its distribution metadata is the one that places it.
			req.Image = image
			if req.ImageDistribution().IsZero() {
				req.ApplyImageDistribution(snapshot.ImageDistribution())
			}
			if meta := req.ImageDistribution(); meta.Mode == models.ImageDistributionAOCR {
				ref := strings.TrimSpace(meta.RegistryRef)
				if ref == "" {
					ref = strings.TrimSpace(req.Image)
				}
				if ref != "" {
					if err := validateClusterArtifactRefArch(ref, hostSnapshotArch()); err != nil {
						return err
					}
				}
			}
		case s.snapshotPusher != nil:
			// Cross-node snapshot lookup: a peer node took the snapshot,
			// pushed it under the deterministic AOCR namespace, but the
			// local store has never seen the row (we don't replicate
			// snapshot rows through the FSM). Construct the canonical
			// AOCR ref and let the docker pull act as the existence
			// check. Only applies to bare identifiers — anything that
			// looks like a registry ref or a local-only build tag goes
			// through the normal classifier below.
			//
			// With no row there is no owner to check, so the ref itself
			// carries the authorization: a user token's ref is built in its
			// own owner's namespace, where only its own snapshots were ever
			// pushed. An operator or internal caller (a failover recreate
			// replaying a stored spec) trusts the AOCR ref the spec already
			// resolved, which can be in any namespace.
			// snapshotAOCRRef always appends `:latest`, so a cross-node
			// snapshot name must be a bare identifier with no tag/digest of
			// its own — otherwise we'd build a double-tagged ref like
			// `snapshots/alpine:3.20:latest` that Docker rejects as
			// "invalid reference format". A tagged ref (e.g. `alpine:3.20`)
			// is a plain base image, not a snapshot, so fall through to the
			// classifier below.
			if imageRegistryHost(req.Image) == "" && !docker.IsLocalOnlyImageRef(req.Image) && !imageRefHasTagOrDigest(req.Image) {
				dest := s.snapshotPusher.DestRefFor(owner, req.Image)
				if meta := req.ImageDistribution(); !scoped && meta.Mode == models.ImageDistributionAOCR && meta.RegistryRef != "" {
					dest = meta.RegistryRef
				}
				if dest != "" {
					if err := validateClusterArtifactRefArch(dest, hostSnapshotArch()); err != nil {
						return err
					}
					req.Image = dest
					if req.ImageDistribution().IsZero() {
						req.ApplyImageDistribution(models.ImageDistributionMetadata{
							Mode:        models.ImageDistributionAOCR,
							RegistryRef: dest,
						})
					}
				}
			}
		}
	}

	meta := req.ImageDistribution()
	if meta.IsZero() {
		classified, err := s.imageDistributionProvider().ClassifyImage(ctx, req.Image)
		if err != nil {
			return err
		}
		meta = classified
	}
	if meta.Mode == models.ImageDistributionAOCR && meta.RegistryRef != "" {
		if err := validateClusterArtifactRefArch(meta.RegistryRef, hostSnapshotArch()); err != nil {
			return err
		}
	}
	normalized, err := normalizeImageDistributionMetadata(req.Image, meta)
	if err != nil {
		return err
	}
	req.ApplyImageDistribution(normalized)
	return nil
}

func (s *Service) normalizeSnapshotImageDistribution(ctx context.Context, snapshot *models.SandboxSnapshot, forceLocal bool) error {
	if s != nil && s.testNormalizeSnapshotErr != nil {
		return s.testNormalizeSnapshotErr
	}
	if snapshot == nil {
		return nil
	}
	snapshot.Image = strings.TrimSpace(snapshot.Image)
	meta := snapshot.ImageDistribution()
	if forceLocal {
		meta.Mode = models.ImageDistributionLocalOnly
		meta.RegistryRef = ""
	}
	if meta.IsZero() {
		classified, err := s.imageDistributionProvider().ClassifyImage(ctx, snapshot.Image)
		if err != nil {
			return err
		}
		meta = classified
	}
	normalized, err := normalizeImageDistributionMetadata(snapshot.Image, meta)
	if err != nil {
		return err
	}
	snapshot.ApplyImageDistribution(normalized)
	return nil
}

func (s *Service) imageDistributionProvider() ImageDistributionProvider {
	if s != nil && s.images != nil {
		return s.images
	}
	return newDefaultImageDistributionProvider("")
}

func normalizeImageDistributionMetadata(image string, meta models.ImageDistributionMetadata) (models.ImageDistributionMetadata, error) {
	mode, err := models.NormalizeImageDistributionMode(meta.Mode)
	if err != nil {
		return models.ImageDistributionMetadata{}, err
	}
	meta.Mode = mode
	meta.Digest = strings.TrimSpace(meta.Digest)
	meta.RegistryRef = strings.TrimSpace(meta.RegistryRef)
	if meta.Mode == "" && strings.TrimSpace(image) != "" {
		meta.Mode = models.ImageDistributionExternalRegistry
	}
	if (meta.Mode == models.ImageDistributionExternalRegistry || meta.Mode == models.ImageDistributionAOCR) && meta.RegistryRef == "" {
		meta.RegistryRef = strings.TrimSpace(image)
	}
	return meta, nil
}

// ImageRequiresLocalPlacement reports a create that must run on the node
// receiving it, because its image exists only there. A pushed snapshot's
// committed image is the exception: a node without it starts the registry
// copy instead (see NormalizeCreateImageDistribution).
func ImageRequiresLocalPlacement(req models.CreateSandboxRequest) bool {
	if req.ImageDistributionMode == models.ImageDistributionLocalOnly {
		return true
	}
	if !docker.IsLocalOnlyImageRef(req.Image) {
		return false
	}
	pushed := req.ImageDistributionMode == models.ImageDistributionAOCR && strings.TrimSpace(req.ImageRegistryRef) != ""
	return !(pushed && docker.IsSnapshotImageRef(req.Image))
}

// imageRefHasTagOrDigest reports whether image carries an explicit `:tag` or
// `@digest`. It inspects only the final path component so a registry host port
// (e.g. `host:5000/repo`) is not mistaken for a tag.
func imageRefHasTagOrDigest(image string) bool {
	image = strings.TrimSpace(image)
	if image == "" {
		return false
	}
	if strings.Contains(image, "@") {
		return true
	}
	last := image
	if idx := strings.LastIndex(image, "/"); idx >= 0 {
		last = image[idx+1:]
	}
	return strings.Contains(last, ":")
}

func imageRegistryHost(image string) string {
	image = strings.TrimSpace(image)
	if image == "" {
		return ""
	}
	if _, after, ok := strings.Cut(image, "://"); ok {
		image = after
	}
	first, _, ok := strings.Cut(image, "/")
	if !ok {
		return ""
	}
	first = strings.ToLower(strings.TrimSpace(first))
	if first == "localhost" || strings.Contains(first, ".") || strings.Contains(first, ":") {
		return first
	}
	return ""
}
