package containerd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	cntr "github.com/containerd/containerd"
	"github.com/containerd/containerd/content"
	"github.com/containerd/containerd/errdefs"
	"github.com/containerd/containerd/images"
	"github.com/containerd/containerd/platforms"
	"github.com/containerd/containerd/rootfs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// snapshotCommitFn is the production snapshot commit seam; tests override it.
var snapshotCommitFn = (*Driver).commitContainerSnapshotLive

// testSnapshotBackend, when non-nil, replaces live containerd snapshot services.
var testSnapshotBackend snapshotBackend

// snapshotBackend is the live containerd surface CreateSnapshot needs.
type snapshotBackend interface {
	loadContainer(ctx context.Context, client *Client, containerRef string) (cntr.Container, error)
	createDiff(ctx context.Context, snapshotKey, snapshotter string, container cntr.Container) (ocispec.Descriptor, error)
	// baseManifestAndConfig reads the base image's manifest and its unmarshalled
	// config, so the commit can extend them with the new diff layer.
	baseManifestAndConfig(ctx context.Context, target ocispec.Descriptor) (ocispec.Manifest, ocispec.Image, error)
	// diffID resolves the uncompressed digest (rootfs diff_id) of a layer blob.
	diffID(ctx context.Context, desc ocispec.Descriptor) (digest.Digest, error)
	// writeBlob content-addresses data and stores it with the given gc labels.
	writeBlob(ctx context.Context, mediaType string, data []byte, labels map[string]string) (ocispec.Descriptor, error)
	createImage(ctx context.Context, img images.Image) (images.Image, error)
	getImage(ctx context.Context, name string) (images.Image, error)
}

type rawSnapshotBackend struct {
	d      *Driver
	client *Client
}

func (b *rawSnapshotBackend) loadContainer(ctx context.Context, _ *Client, containerRef string) (cntr.Container, error) {
	return b.d.loadContainerForRef(ctx, b.client, containerRef)
}

func (b *rawSnapshotBackend) createDiff(ctx context.Context, snapshotKey, snapshotter string, _ cntr.Container) (ocispec.Descriptor, error) {
	raw := b.client.Raw()
	if raw == nil {
		return ocispec.Descriptor{}, errors.New("snapshot diff requires live containerd")
	}
	return rootfs.CreateDiff(ctx, snapshotKey, raw.SnapshotService(snapshotter), raw.DiffService())
}

func (b *rawSnapshotBackend) createImage(ctx context.Context, img images.Image) (images.Image, error) {
	raw := b.client.Raw()
	if raw == nil {
		return images.Image{}, errors.New("snapshot image create requires live containerd")
	}
	return raw.ImageService().Create(ctx, img)
}

func (b *rawSnapshotBackend) getImage(ctx context.Context, name string) (images.Image, error) {
	raw := b.client.Raw()
	if raw == nil {
		return images.Image{}, errors.New("snapshot image get requires live containerd")
	}
	return raw.ImageService().Get(ctx, name)
}

func (b *rawSnapshotBackend) baseManifestAndConfig(ctx context.Context, target ocispec.Descriptor) (ocispec.Manifest, ocispec.Image, error) {
	raw := b.client.Raw()
	if raw == nil {
		return ocispec.Manifest{}, ocispec.Image{}, errors.New("snapshot base read requires live containerd")
	}
	cs := raw.ContentStore()
	manifest, err := images.Manifest(ctx, cs, target, platforms.Default())
	if err != nil {
		return ocispec.Manifest{}, ocispec.Image{}, fmt.Errorf("read base manifest: %w", err)
	}
	configBytes, err := content.ReadBlob(ctx, cs, manifest.Config)
	if err != nil {
		return ocispec.Manifest{}, ocispec.Image{}, fmt.Errorf("read base config: %w", err)
	}
	var config ocispec.Image
	if err := json.Unmarshal(configBytes, &config); err != nil {
		return ocispec.Manifest{}, ocispec.Image{}, fmt.Errorf("parse base config: %w", err)
	}
	return manifest, config, nil
}

func (b *rawSnapshotBackend) diffID(ctx context.Context, desc ocispec.Descriptor) (digest.Digest, error) {
	raw := b.client.Raw()
	if raw == nil {
		return "", errors.New("snapshot diff id requires live containerd")
	}
	return images.GetDiffID(ctx, raw.ContentStore(), desc)
}

func (b *rawSnapshotBackend) writeBlob(ctx context.Context, mediaType string, data []byte, labels map[string]string) (ocispec.Descriptor, error) {
	raw := b.client.Raw()
	if raw == nil {
		return ocispec.Descriptor{}, errors.New("snapshot write blob requires live containerd")
	}
	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(data),
		Size:      int64(len(data)),
	}
	ref := "aerolvm-snapshot-" + desc.Digest.String()
	var opts []content.Opt
	if len(labels) > 0 {
		opts = append(opts, content.WithLabels(labels))
	}
	if err := content.WriteBlob(ctx, raw.ContentStore(), ref, bytes.NewReader(data), desc, opts...); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("write %s blob: %w", mediaType, err)
	}
	return desc, nil
}

func resolveSnapshotBackend(d *Driver, client *Client) snapshotBackend {
	if testSnapshotBackend != nil {
		return testSnapshotBackend
	}
	if client == nil || client.Raw() == nil {
		return nil
	}
	return &rawSnapshotBackend{d: d, client: client}
}

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
	backend := resolveSnapshotBackend(d, client)
	if backend == nil {
		return "", errors.New("containerd snapshot commit requires live containerd")
	}
	container, err := backend.loadContainer(ctx, client, containerRef)
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
	desc, err := backend.createDiff(ctx, info.SnapshotKey, info.Snapshotter, container)
	if err != nil {
		return "", fmt.Errorf("snapshot diff: %w", err)
	}
	baseImage := strings.TrimSpace(info.Image)
	if baseImage == "" {
		return "", errors.New("snapshot container has no base image reference")
	}
	base, err := backend.getImage(ctx, baseImage)
	if err != nil {
		return "", fmt.Errorf("snapshot base image %q: %w", baseImage, err)
	}
	img, err := assembleCommittedImage(ctx, backend, base.Target, desc, imageRef, time.Now().UTC())
	if err != nil {
		return "", err
	}
	created, err := backend.createImage(ctx, img)
	if err != nil {
		if errdefs.IsAlreadyExists(err) {
			existing, getErr := backend.getImage(ctx, imageRef)
			if getErr != nil {
				return "", fmt.Errorf("snapshot image exists: %w", err)
			}
			return imageDigestID(existing.Target), nil
		}
		return "", fmt.Errorf("snapshot image create: %w", err)
	}
	return imageDigestID(created.Target), nil
}

// assembleCommittedImage builds a runnable/pushable OCI image from the base
// image plus the new diff layer: it extends the base config's rootfs.diff_ids
// and the base manifest's layers, writes the new config and manifest blobs
// (with gc.ref labels so containerd's GC keeps the config + every layer), and
// returns an image record targeting the new MANIFEST.
//
// The previous code assigned the diff-LAYER descriptor as the image Target, so
// the "image" was not a manifest and could neither be run (WithNewSnapshot) nor
// pushed. This assembly is verified offline for structure (config/manifest
// shape + gc.ref labels) via the fake backend; the live content-store write and
// a commit→re-run/push round trip are integration-suite territory (darwin has
// no containerd content store).
func assembleCommittedImage(ctx context.Context, backend snapshotBackend, baseTarget, diffDesc ocispec.Descriptor, imageRef string, now time.Time) (images.Image, error) {
	manifest, config, err := backend.baseManifestAndConfig(ctx, baseTarget)
	if err != nil {
		return images.Image{}, err
	}
	diffID, err := backend.diffID(ctx, diffDesc)
	if err != nil {
		return images.Image{}, fmt.Errorf("snapshot diff id: %w", err)
	}
	config.RootFS.DiffIDs = append(config.RootFS.DiffIDs, diffID)
	config.History = append(config.History, ocispec.History{
		Created:   &now,
		CreatedBy: "aerolvm snapshot commit",
		Comment:   imageRef,
	})
	configBytes, err := json.Marshal(config)
	if err != nil {
		return images.Image{}, fmt.Errorf("marshal snapshot config: %w", err)
	}
	configDesc, err := backend.writeBlob(ctx, ocispec.MediaTypeImageConfig, configBytes, nil)
	if err != nil {
		return images.Image{}, err
	}
	manifest.Config = configDesc
	manifest.Layers = append(manifest.Layers, diffDesc)
	if manifest.MediaType == "" {
		manifest.MediaType = ocispec.MediaTypeImageManifest
	}
	if manifest.SchemaVersion == 0 {
		manifest.SchemaVersion = 2
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		return images.Image{}, fmt.Errorf("marshal snapshot manifest: %w", err)
	}
	// GC ref labels: without them containerd's GC reaps the config and layer
	// blobs the manifest references, breaking the image out from under itself.
	refLabels := map[string]string{"containerd.io/gc.ref.content.config": configDesc.Digest.String()}
	for i, layer := range manifest.Layers {
		refLabels[fmt.Sprintf("containerd.io/gc.ref.content.l.%d", i)] = layer.Digest.String()
	}
	manifestDesc, err := backend.writeBlob(ctx, ocispec.MediaTypeImageManifest, manifestBytes, refLabels)
	if err != nil {
		return images.Image{}, err
	}
	return images.Image{
		Name:   imageRef,
		Target: manifestDesc,
		Labels: map[string]string{"containerd.io/gc.root": now.Format(time.RFC3339Nano)},
	}, nil
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
