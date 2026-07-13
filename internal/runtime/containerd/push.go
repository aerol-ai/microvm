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
	img, err := client.GetImage(ctx, source)
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
			return "", fmt.Errorf("containerd push: create dest name: %w", err)
		}
	} else if _, err := isvc.Update(ctx, images.Image{Name: dest, Target: target}, "target"); err != nil {
		// Name already exists; push with the source descriptor anyway.
		_ = err
	}

	refHost := registryHost(dest)
	opts := []cntr.RemoteOpt{
		cntr.WithResolver(ctddocker.NewResolver(ctddocker.ResolverOptions{
			Authorizer: ctddocker.NewDockerAuthorizer(ctddocker.WithAuthCreds(func(host string) (string, string, error) {
				if refHost != "" && host != refHost && host != strings.TrimSpace(auth.Server) {
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
