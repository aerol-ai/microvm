package containerd

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/images/archive"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// A Firecracker snapshot is a stopped VM's root filesystem as a one-layer
// image (internal/runtime/firecracker CreateSnapshot). On a containerd node
// it lands in this engine's aerolvm namespace, beside this engine's own
// commits, so the registry pusher, the delete and image GC see one kind of
// snapshot image whichever runtime made it.

// ImportRootfsImage makes rootfs, a tar of a filesystem tree, the single
// layer of a new image imageRef, unpacked so a container can run it, and
// returns the image ID (its manifest digest). An image already under that
// name is repointed at the new one.
func (d *Driver) ImportRootfsImage(ctx context.Context, imageRef string, rootfs io.Reader) (string, error) {
	fullRef, err := formatSnapshotImageRef(imageRef)
	if err != nil {
		return "", err
	}
	client, err := d.ensureClient()
	if err != nil {
		return "", err
	}
	backend := resolveSnapshotBackend(d, client)
	if backend == nil {
		return "", errors.New("containerd image import requires live containerd")
	}
	// The layer is written with no gc reference until the image's labels
	// land; the lease keeps GC off it until then (see the commit path).
	if ls := leasesServiceFn(client); ls != nil {
		lease, err := ls.Create(ctx, leases.WithRandomID(), leases.WithExpiration(leaseExpiry))
		if err != nil {
			return "", fmt.Errorf("import lease: %w", err)
		}
		ctx = leases.WithLease(ctx, lease.ID)
		// Released even when the caller gave up; it would expire anyway.
		defer func() { _ = ls.Delete(context.WithoutCancel(ctx), lease) }()
	}
	layer, diffID, err := backend.writeLayer(ctx, fullRef, rootfs)
	if err != nil {
		return "", fmt.Errorf("import layer: %w", err)
	}
	img, err := assembleRootfsImage(ctx, backend, layer, diffID, fullRef, time.Now().UTC())
	if err != nil {
		return "", err
	}
	created, err := backend.createImage(ctx, img)
	if errdefs.IsAlreadyExists(err) {
		created, err = backend.updateImage(ctx, img)
	}
	if err != nil {
		return "", fmt.Errorf("import image record: %w", err)
	}
	// Unpacked like a pulled image (WithPullUnpack), so a container create
	// from it finds its layers in the default snapshotter.
	if err := backend.unpack(ctx, fullRef, ""); err != nil {
		return "", fmt.Errorf("import unpack: %w", err)
	}
	return imageDigestID(created.Target), nil
}

// assembleRootfsImage writes the config and manifest of a one-layer image for
// this host's platform, with the gc.ref labels that keep the config and layer,
// and returns the image record targeting the manifest.
func assembleRootfsImage(ctx context.Context, backend snapshotBackend, layer ocispec.Descriptor, diffID digest.Digest, imageRef string, now time.Time) (images.Image, error) {
	// A VM disk is a Linux filesystem whatever the host runs; its CPU
	// architecture is the host's (the guest runs on it).
	platform := platforms.DefaultSpec()
	config := ocispec.Image{
		Created:  &now,
		Platform: ocispec.Platform{OS: "linux", Architecture: platform.Architecture, Variant: platform.Variant},
		RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{diffID}},
		History: []ocispec.History{{
			Created:   &now,
			CreatedBy: "aerolvm firecracker snapshot",
			Comment:   imageRef,
		}},
	}
	configDesc, err := writeJSONBlob(ctx, backend, ocispec.MediaTypeImageConfig, config, nil)
	if err != nil {
		return images.Image{}, err
	}
	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    []ocispec.Descriptor{layer},
	}
	manifestDesc, err := writeJSONBlob(ctx, backend, ocispec.MediaTypeImageManifest, manifest, map[string]string{
		"containerd.io/gc.ref.content.config": configDesc.Digest.String(),
		"containerd.io/gc.ref.content.l.0":    layer.Digest.String(),
	})
	if err != nil {
		return images.Image{}, err
	}
	return images.Image{
		Name:   imageRef,
		Target: manifestDesc,
		Labels: map[string]string{"containerd.io/gc.root": now.Format(time.RFC3339Nano)},
	}, nil
}

func writeJSONBlob(ctx context.Context, backend snapshotBackend, mediaType string, v any, labels map[string]string) (ocispec.Descriptor, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("marshal %s: %w", mediaType, err)
	}
	return backend.writeBlob(ctx, mediaType, data, labels)
}

// ExportImageArchive writes the local image imageRef to w as an OCI archive
// (skopeo's oci-archive: transport reads it). ok is false, with nothing
// written, when the namespace has no such image.
func (d *Driver) ExportImageArchive(ctx context.Context, imageRef string, w io.Writer) (bool, error) {
	fullRef, err := formatSnapshotImageRef(imageRef)
	if err != nil {
		return false, err
	}
	client, err := d.ensureClient()
	if err != nil {
		return false, err
	}
	backend := resolveSnapshotBackend(d, client)
	if backend == nil {
		return false, errors.New("containerd image export requires live containerd")
	}
	if _, err := backend.getImage(ctx, fullRef); errdefs.IsNotFound(err) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if err := backend.exportImage(ctx, fullRef, w); err != nil {
		return false, fmt.Errorf("export image %s: %w", fullRef, err)
	}
	return true, nil
}

// writeLayer streams rootfs into the content store gzipped, hashing it on the
// way, and returns the layer descriptor and the uncompressed digest (the
// rootfs diff_id). Nothing is held in memory or staged on disk.
func (b *rawSnapshotBackend) writeLayer(ctx context.Context, ref string, rootfs io.Reader) (ocispec.Descriptor, digest.Digest, error) {
	cs := snapshotContentStoreFn(b.client)
	if cs == nil {
		return ocispec.Descriptor{}, "", errors.New("layer write requires live containerd")
	}
	w, err := content.OpenWriter(ctx, cs, content.WithRef("aerolvm-rootfs-import-"+strings.ReplaceAll(ref, "/", "_")))
	if err != nil {
		return ocispec.Descriptor{}, "", err
	}
	defer w.Close()
	return gzipLayer(ctx, w, rootfs)
}

// layerWriter is the part of a content.Writer gzipLayer uses.
type layerWriter interface {
	io.Writer
	Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error
	Digest() digest.Digest
}

// gzipLayer compresses rootfs into w, commits it, and returns the gzip
// layer's descriptor and rootfs's own (uncompressed) digest.
func gzipLayer(ctx context.Context, w layerWriter, rootfs io.Reader) (ocispec.Descriptor, digest.Digest, error) {
	counter := &countingWriter{w: w}
	gz := gzip.NewWriter(counter)
	diff := digest.Canonical.Digester()
	if _, err := io.Copy(io.MultiWriter(gz, diff.Hash()), rootfs); err != nil {
		return ocispec.Descriptor{}, "", fmt.Errorf("compress layer: %w", err)
	}
	if err := gz.Close(); err != nil {
		return ocispec.Descriptor{}, "", fmt.Errorf("compress layer: %w", err)
	}
	// Size and digest 0/"": the store takes what was written. An identical
	// layer already in the store is not an error.
	if err := w.Commit(ctx, 0, ""); err != nil && !errdefs.IsAlreadyExists(err) {
		return ocispec.Descriptor{}, "", fmt.Errorf("commit layer: %w", err)
	}
	return ocispec.Descriptor{
		MediaType: ocispec.MediaTypeImageLayerGzip,
		Digest:    w.Digest(),
		Size:      counter.n,
	}, diff.Digest(), nil
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func (b *rawSnapshotBackend) updateImage(ctx context.Context, img images.Image) (images.Image, error) {
	raw := b.client.Raw()
	if raw == nil {
		return images.Image{}, errors.New("image update requires live containerd")
	}
	return raw.ImageService().Update(ctx, img, "target", "labels")
}

func (b *rawSnapshotBackend) exportImage(ctx context.Context, name string, w io.Writer) error {
	raw := b.client.Raw()
	if raw == nil {
		return errors.New("image export requires live containerd")
	}
	return raw.Export(ctx, w,
		archive.WithImage(raw.ImageService(), name),
		archive.WithPlatform(platforms.DefaultStrict()))
}
