package containerd

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	ctddocker "github.com/containerd/containerd/remotes/docker"
)

// RegistryPusher pushes local aerolvm-namespace images to a remote registry
// (AOCR snapshot path). Implements service.SnapshotPushDocker so the existing
// SnapshotPusher / reconciler work unchanged under SB_CONTAINER_ENGINE=containerd.
type RegistryPusher struct {
	driver *Driver
	// pushFn is a test seam over the live Push + ImageService path.
	pushFn func(ctx context.Context, source, dest string, auth models.RegistryAuth) (digest string, err error)
}

// NewRegistryPusher returns a SnapshotPushDocker backed by the containerd driver.
func NewRegistryPusher(d *Driver) *RegistryPusher {
	return &RegistryPusher{driver: d}
}

// PushImage tags SourceTag as DestRef in the aerolvm namespace and pushes it.
func (p *RegistryPusher) PushImage(ctx context.Context, req docker.PushImageRequest) (string, error) {
	if p == nil {
		return "", errors.New("containerd registry pusher is nil")
	}
	src := strings.TrimSpace(req.SourceTag)
	dest := strings.TrimSpace(req.DestRef)
	if src == "" {
		return "", errors.New("push image: source tag is required")
	}
	if dest == "" {
		return "", errors.New("push image: dest ref is required")
	}
	if req.Auth.Username == "" || req.Auth.Password == "" {
		return "", errors.New("push image: auth username and password are required")
	}

	push := p.pushFn
	if push == nil {
		push = p.livePush
	}
	digest, err := push(ctx, src, dest, req.Auth)
	if err != nil {
		return "", err
	}
	if req.OnDigest != nil && digest != "" {
		req.OnDigest(digest)
	}
	if req.OnLog != nil {
		req.OnLog("pushed " + dest)
	}
	return dest, nil
}

func (p *RegistryPusher) livePush(ctx context.Context, source, dest string, auth models.RegistryAuth) (string, error) {
	if p.driver == nil {
		return "", errors.New("containerd push: driver is nil")
	}
	client, err := p.driver.ensureClient()
	if err != nil {
		return "", fmt.Errorf("containerd push: %w", err)
	}
	// Snapshots are committed locally as "<name>:latest" (formatSnapshotImageRef
	// normalizes a tagless name), but the snapshot-push reconciler passes the
	// bare "<name>". GetImage is exact-match, so a single bare lookup missed and
	// every containerd snapshot push failed "image not found" — the image never
	// reached AOCR and cross-node create-from-snapshot broke (single-node found
	// it locally and never needed the push). Try the exact ref, then
	// "<name>:latest", mirroring the create/pull path (ImageExists / ensureImage).
	var img cntr.Image
	for _, candidate := range pushSourceCandidates(source) {
		if img, err = client.GetImage(ctx, candidate); err == nil {
			break
		}
	}
	if err != nil {
		return "", fmt.Errorf("containerd push: get %s: %w", source, err)
	}
	raw := client.Raw()
	if raw == nil {
		return "", errors.New("containerd push: live client required")
	}
	target := img.Target()
	isvc := raw.ImageService()
	if _, err := isvc.Get(ctx, dest); err != nil {
		if !errdefs.IsNotFound(err) {
			return "", fmt.Errorf("containerd push: lookup dest: %w", err)
		}
		if _, err := isvc.Create(ctx, images.Image{Name: dest, Target: target}); err != nil {
			// A concurrent duplicate push may have created the name first — that
			// is success, not an error (pr-review §1 idempotency). Fall through to
			// the Push below with the same target.
			if !errdefs.IsAlreadyExists(err) {
				return "", fmt.Errorf("containerd push: create dest name: %w", err)
			}
		}
	} else if _, err := isvc.Update(ctx, images.Image{Name: dest, Target: target}, "target"); err != nil {
		// Name already exists; push with the source descriptor anyway.
		_ = err
	}

	// Scope creds to exactly one registry host; never broadcast them to every
	// host the resolver dials (foreign-layer / redirect hosts). A hostless dest
	// ref falls back to auth.Server, and if neither resolves a host we refuse
	// rather than leak credentials.
	scopeHost, err := pushCredScopeHost(dest, auth.Server)
	if err != nil {
		return "", err
	}
	opts := []cntr.RemoteOpt{
		cntr.WithResolver(ctddocker.NewResolver(ctddocker.ResolverOptions{
			Authorizer: ctddocker.NewDockerAuthorizer(ctddocker.WithAuthCreds(func(host string) (string, string, error) {
				if host != scopeHost {
					return "", "", nil
				}
				return auth.Username, auth.Password, nil
			})),
		})),
	}
	if err := raw.Push(ctx, dest, target, opts...); err != nil {
		return "", fmt.Errorf("containerd push %s -> %s: %w", source, dest, err)
	}
	return string(target.Digest), nil
}

// pushSourceCandidates lists the local image refs livePush tries, in order, to
// resolve the source image to upload. Snapshots are committed as "<name>:latest"
// (formatSnapshotImageRef normalizes a tagless name), but the snapshot-push
// reconciler passes the bare "<name>"; containerd's GetImage is exact-match, so
// without the ":latest" fallback the push failed "image not found" and the
// snapshot never reached AOCR, breaking cross-node create-from-snapshot. Mirrors
// the create/pull path's exact-then-":latest" resolution (see ImageExists). A
// ref that already carries a tag or digest is used as-is.
func pushSourceCandidates(source string) []string {
	if refHasTag(source) {
		return []string{source}
	}
	return []string{source, source + ":latest"}
}

// pushCredScopeHost resolves the single registry host that push credentials may
// be sent to: the dest ref's own host, or (for a hostless ref) the configured
// auth server. Returns an error rather than "" so a bad ref can never widen the
// cred scope to every host the resolver contacts.
func pushCredScopeHost(dest, authServer string) (string, error) {
	if h := registryHost(dest); h != "" {
		return h, nil
	}
	if h := strings.TrimSpace(authServer); h != "" {
		return h, nil
	}
	return "", fmt.Errorf("containerd push: cannot determine registry host for dest %q; refusing to broadcast credentials", dest)
}
