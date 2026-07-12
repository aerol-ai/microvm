package containerd

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/rootfs"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// snapshotCommitFn is the production snapshot commit seam; tests override it.
var snapshotCommitFn = (*Driver).commitContainerSnapshotLive

// CreateSnapshot commits a running task filesystem into a new image in the
// aerolvm namespace (plans/containerd-engine.md Phase 3).
func (d *Driver) CreateSnapshot(ctx context.Context, containerRef, imageRef string) (string, error) {
	containerRef = strings.TrimSpace(containerRef)
	if containerRef == "" {
		return "", errors.New("container ref is required")
	}
	fullRef, err := formatSnapshotImageRef(imageRef)
	if err != nil {
		return "", err
	}
	client, err := d.ensureClient()
	if err != nil {
		return "", err
	}
	return snapshotCommitFn(d, ctx, client, containerRef, fullRef)
}

func formatSnapshotImageRef(imageRef string) (string, error) {
	repo, tag, err := splitSnapshotImageRef(imageRef)
	if err != nil {
		return "", err
	}
	if tag == "" {
		tag = "latest"
	}
	return repo + ":" + tag, nil
}

func splitSnapshotImageRef(imageRef string) (repo, tag string, err error) {
	trimmed := strings.TrimSpace(imageRef)
	if trimmed == "" {
		return "", "", errors.New("snapshot name is required")
	}
	if strings.Contains(trimmed, "@") {
		return "", "", errors.New("snapshot name must not include a digest")
	}
	lastSlash := strings.LastIndex(trimmed, "/")
	lastColon := strings.LastIndex(trimmed, ":")
	if lastColon > lastSlash {
		repo = trimmed[:lastColon]
		tag = trimmed[lastColon+1:]
		if strings.TrimSpace(repo) == "" || strings.TrimSpace(tag) == "" {
			return "", "", errors.New("snapshot name must be a valid image reference")
		}
		return repo, tag, nil
	}
	return trimmed, "", nil
}

func (d *Driver) commitContainerSnapshotLive(ctx context.Context, client *Client, containerRef, imageRef string) (string, error) {
	raw := client.Raw()
	if raw == nil {
		return "", errors.New("containerd snapshot commit requires live containerd")
	}
	container, err := d.loadContainerForRef(ctx, client, containerRef)
	if err != nil {
		return "", err
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("snapshot task: %w", err)
	}
	wasRunning := false
	if status, statusErr := task.Status(ctx); statusErr == nil && status.Status == cntr.Running {
		wasRunning = true
		if err := task.Pause(ctx); err != nil {
			return "", fmt.Errorf("snapshot pause: %w", err)
		}
	}
	defer func() {
		if wasRunning {
			_ = task.Resume(ctx)
		}
	}()

	info, err := container.Info(ctx)
	if err != nil {
		return "", fmt.Errorf("snapshot container info: %w", err)
	}
	if info.SnapshotKey == "" || info.Snapshotter == "" {
		return "", errors.New("snapshot container has no rootfs snapshot")
	}
	ss := raw.SnapshotService(info.Snapshotter)
	desc, err := rootfs.CreateDiff(ctx, info.SnapshotKey, ss, raw.DiffService())
	if err != nil {
		return "", fmt.Errorf("snapshot diff: %w", err)
	}
	now := time.Now().UTC()
	img := images.Image{
		Name:   imageRef,
		Target: desc,
		Labels: map[string]string{
			"containerd.io/gc.root": now.Format(time.RFC3339Nano),
		},
	}
	created, err := raw.ImageService().Create(ctx, img)
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			existing, getErr := raw.ImageService().Get(ctx, imageRef)
			if getErr != nil {
				return "", fmt.Errorf("snapshot image exists: %w", err)
			}
			return imageDigestID(existing.Target), nil
		}
		return "", fmt.Errorf("snapshot image create: %w", err)
	}
	return imageDigestID(created.Target), nil
}

func (d *Driver) loadContainerForRef(ctx context.Context, client *Client, containerRef string) (cntr.Container, error) {
	container, err := client.LoadContainer(ctx, containerRef)
	if err == nil {
		return container, nil
	}
	if !errdefs.IsNotFound(err) {
		return nil, err
	}
	containers, listErr := client.ListContainers(ctx, "labels."+sandboxIDLabelKey+"=="+containerRef)
	if listErr != nil {
		return nil, listErr
	}
	if len(containers) == 0 {
		return nil, errdefs.ErrNotFound
	}
	return containers[0], nil
}

func imageDigestID(desc ocispec.Descriptor) string {
	return strings.TrimSpace(desc.Digest.String())
}
