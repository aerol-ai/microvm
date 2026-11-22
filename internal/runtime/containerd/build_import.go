package containerd

import (
	"archive/tar"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/leases"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// A rootless BuildKit build (plans/security-gaps-m1-m4.md §3.5 PR 10b, eng
// review D14) cannot write into containerd: its daemon runs as a user with
// no rights. It exports the image as an OCI archive instead, and sandboxd
// imports it here, with the same containerd calls a pull makes: content
// writes, an image record, and an unpack. In privilege mode split those go
// through the root helper's gate, which checks each one, so the archive is
// read by sandboxd, which has no rights, and never by root. containerd's
// transfer service, which would read the archive as root, stays refused at
// the gate.
//
// The archive comes from the process that ran the build's steps, so it is
// untrusted input. ingestBuildArchive reads it under these rules:
//   - only an OCI image layout: oci-layout, index.json and blobs/sha256/<hex>,
//     the three folders above them, and nothing else (no Docker
//     manifest.json, no links, no devices, no sparse files: a sparse entry
//     describes any size of zeros in a few bytes);
//   - at most maxBytes, both read and declared by the entries' headers, at
//     most maxBuildArchiveEntries entries, small caps on the two JSON files,
//     and maxBuildManifestBytes on each blob that is read whole: the image
//     the index names, each manifest or index an index names, and each
//     manifest's config. Those are checked by their place in the image, not
//     by the media type their descriptor claims (containerd's unpack reads
//     a manifest's config whole whatever it is called), and by the
//     descriptor's size, before reading. Each must also be of the kind its
//     place holds: an index names manifests or indexes, a manifest names an
//     image config and layers;
//   - every blob's bytes hash to the name it carries, even when containerd
//     already holds that content: a build names only content it supplies,
//     so it can never pick up another image's layer by its digest;
//   - index.json names exactly one image, and the name it gets is the
//     build's own tag, never a name inside the archive.

// Caps on the two JSON files an OCI layout carries. The layout file is one
// short object; BuildKit's index names one image.
const (
	maxBuildLayoutBytes = 4 << 10
	maxBuildIndexBytes  = 1 << 20
	// maxBuildManifestBytes caps each manifest, index and config, which
	// are read whole into memory: the size a registry pull allows a
	// manifest (containerd's remotes, 4 MiB).
	maxBuildManifestBytes = 4 << 20
	// maxBuildArchiveEntries caps the entries an archive may hold. Each
	// blob is a containerd write (through the gate in split mode), and
	// containerd's own image walk stops at 10,000 children.
	maxBuildArchiveEntries = 10000
)

// errBuildArchiveTooLarge is returned once an archive passes its bound.
var errBuildArchiveTooLarge = errors.New("the build's image archive is larger than SB_CONTAINERD_BUILD_MAX_IMAGE_BYTES allows")

// ImportBuildArchive reads a rootless build's OCI archive from archive and
// makes it the image ref, unpacked so a container can run it. finished is
// asked, once the archive has been read, whether the process that wrote it
// succeeded; only then is the image named. A nil finished counts as success.
// An image already under ref is repointed, as BuildKit's own exporter does.
// On any failure no image record is left under ref by this call, and the
// content it wrote is left to containerd's garbage collector (its lease
// ends here).
func (d *Driver) ImportBuildArchive(ctx context.Context, ref string, archive io.Reader, maxBytes int64, finished func() error) error {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return errors.New("build import: an image name is required")
	}
	if maxBytes <= 0 {
		return errors.New("build import: the archive bound must be positive")
	}
	client, err := d.ensureClient()
	if err != nil {
		return err
	}
	backend := resolveSnapshotBackend(d, client)
	cs := snapshotContentStoreFn(client)
	if backend == nil || cs == nil {
		return errors.New("build import requires live containerd")
	}
	// Blobs are written with no gc reference until the labels and the image
	// record land; the lease keeps GC off them until then, as for the
	// Firecracker rootfs import.
	if ls := leasesServiceFn(client); ls != nil {
		lease, err := ls.Create(ctx, leases.WithRandomID(), leases.WithExpiration(leaseExpiry))
		if err != nil {
			return fmt.Errorf("build import lease: %w", err)
		}
		ctx = leases.WithLease(ctx, lease.ID)
		defer func() { _ = ls.Delete(context.WithoutCancel(ctx), lease) }()
	}
	target, blobs, err := ingestBuildArchive(ctx, cs, archive, maxBytes)
	if err != nil {
		return err
	}
	if finished != nil {
		if err := finished(); err != nil {
			return err
		}
	}
	if err := labelBuildImage(ctx, cs, target, blobs); err != nil {
		return err
	}
	img := images.Image{Name: ref, Target: target}
	if _, err := backend.createImage(ctx, img); errdefs.IsAlreadyExists(err) {
		_, err = backend.updateImage(ctx, img)
		if err != nil {
			return fmt.Errorf("build import image record: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("build import image record: %w", err)
	}
	if err := backend.unpack(ctx, ref, ""); err != nil {
		return removeFailedImageRecord(ctx, backend, ref, fmt.Errorf("build import unpack: %w", err))
	}
	return nil
}

// ingestBuildArchive writes every blob of an OCI layout archive into cs and
// returns the one image its index names, with the size of each blob it
// wrote. See the rules above ImportBuildArchive.
func ingestBuildArchive(ctx context.Context, cs content.Ingester, archive io.Reader, maxBytes int64) (ocispec.Descriptor, map[digest.Digest]int64, error) {
	tr := tar.NewReader(&boundedReader{r: archive, left: maxBytes})
	blobs := map[digest.Digest]int64{}
	var layout, index []byte
	var entries int
	var declared int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return ocispec.Descriptor{}, nil, fmt.Errorf("read the build's image archive: %w", err)
		}
		if entries++; entries > maxBuildArchiveEntries {
			return ocispec.Descriptor{}, nil, fmt.Errorf("the build's image archive has more than %d entries", maxBuildArchiveEntries)
		}
		name := strings.TrimPrefix(hdr.Name, "./")
		switch hdr.Typeflag {
		case tar.TypeDir:
			if clean := path.Clean(name); clean != "blobs" && clean != "blobs/sha256" && clean != "." {
				return ocispec.Descriptor{}, nil, fmt.Errorf("the build's image archive has an unexpected folder %.64q", hdr.Name)
			}
			continue
		case tar.TypeReg:
			// The size a header declares is what an entry becomes; a sparse
			// one declares far more than the archive carries.
			if isSparse(hdr) {
				return ocispec.Descriptor{}, nil, fmt.Errorf("the build's image archive entry %.64q is a sparse file", hdr.Name)
			}
			if hdr.Size < 0 || hdr.Size > maxBytes-declared {
				return ocispec.Descriptor{}, nil, fmt.Errorf("%w: its entries declare more than %d bytes", errBuildArchiveTooLarge, maxBytes)
			}
			declared += hdr.Size
		default:
			return ocispec.Descriptor{}, nil, fmt.Errorf("the build's image archive entry %.64q is not a file or folder", hdr.Name)
		}
		switch {
		case name == ocispec.ImageLayoutFile:
			if layout != nil {
				return ocispec.Descriptor{}, nil, errors.New("the build's image archive has two oci-layout files")
			}
			if layout, err = readCapped(tr, hdr.Size, maxBuildLayoutBytes, name); err != nil {
				return ocispec.Descriptor{}, nil, err
			}
		case name == ocispec.ImageIndexFile:
			if index != nil {
				return ocispec.Descriptor{}, nil, errors.New("the build's image archive has two index.json files")
			}
			if index, err = readCapped(tr, hdr.Size, maxBuildIndexBytes, name); err != nil {
				return ocispec.Descriptor{}, nil, err
			}
		case strings.HasPrefix(name, "blobs/sha256/"):
			dgst, err := blobDigest(strings.TrimPrefix(name, "blobs/sha256/"))
			if err != nil {
				return ocispec.Descriptor{}, nil, err
			}
			if _, dup := blobs[dgst]; dup {
				return ocispec.Descriptor{}, nil, fmt.Errorf("the build's image archive carries blob %s twice", dgst)
			}
			if err := writeBuildBlob(ctx, cs, tr, dgst, hdr.Size); err != nil {
				return ocispec.Descriptor{}, nil, err
			}
			blobs[dgst] = hdr.Size
		default:
			return ocispec.Descriptor{}, nil, fmt.Errorf("the build's image archive has an unexpected file %.64q", hdr.Name)
		}
	}
	target, err := buildArchiveTarget(layout, index, blobs)
	if err != nil {
		return ocispec.Descriptor{}, nil, err
	}
	return target, blobs, nil
}

// buildArchiveTarget checks the layout and index files and returns the one
// image the index names, as a bare descriptor: the archive's annotations
// (BuildKit puts its own image name there) and platform are dropped.
func buildArchiveTarget(layout, index []byte, blobs map[digest.Digest]int64) (ocispec.Descriptor, error) {
	if layout == nil || index == nil {
		return ocispec.Descriptor{}, errors.New("the build's image archive is not an OCI image layout (oci-layout or index.json is missing)")
	}
	var l ocispec.ImageLayout
	if err := json.Unmarshal(layout, &l); err != nil || l.Version != ocispec.ImageLayoutVersion {
		return ocispec.Descriptor{}, fmt.Errorf("the build's image archive has OCI layout version %q, want %q", l.Version, ocispec.ImageLayoutVersion)
	}
	var idx ocispec.Index
	if err := json.Unmarshal(index, &idx); err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("the build's image index: %w", err)
	}
	if idx.SchemaVersion != 2 || (idx.MediaType != "" && idx.MediaType != ocispec.MediaTypeImageIndex) {
		return ocispec.Descriptor{}, fmt.Errorf("the build's image index has schema %d and media type %q, want an OCI image index", idx.SchemaVersion, idx.MediaType)
	}
	if len(idx.Manifests) != 1 {
		return ocispec.Descriptor{}, fmt.Errorf("the build's image index names %d images, want exactly one", len(idx.Manifests))
	}
	m := idx.Manifests[0]
	switch m.MediaType {
	case ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex,
		images.MediaTypeDockerSchema2Manifest, images.MediaTypeDockerSchema2ManifestList:
	default:
		return ocispec.Descriptor{}, fmt.Errorf("the build's image has media type %.64q, want an image manifest or index", m.MediaType)
	}
	if err := m.Digest.Validate(); err != nil || m.Digest.Algorithm() != digest.SHA256 {
		return ocispec.Descriptor{}, fmt.Errorf("the build's image digest %.80q is not a sha256 digest", m.Digest)
	}
	size, ok := blobs[m.Digest]
	if !ok || size != m.Size {
		return ocispec.Descriptor{}, fmt.Errorf("the build's image %s is not in its archive at size %d", m.Digest, m.Size)
	}
	if err := checkReadWholeSize("the image", m); err != nil {
		return ocispec.Descriptor{}, err
	}
	return ocispec.Descriptor{MediaType: m.MediaType, Digest: m.Digest, Size: m.Size}, nil
}

// labelBuildImage walks the image from target, for this host's platform,
// and labels each manifest and index with its children, as a pull does, so
// containerd's garbage collector keeps them once the import's lease ends.
// Every child must be a blob the archive carried, of the kind its place in
// the image holds, and no larger than maxBuildManifestBytes where it is
// read whole (buildChildren).
func labelBuildImage(ctx context.Context, cs content.Store, target ocispec.Descriptor, blobs map[digest.Digest]int64) error {
	carried := images.HandlerFunc(func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		return buildChildren(ctx, cs, desc)
	})
	var walk images.HandlerFunc = func(ctx context.Context, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
		children, err := images.FilterPlatforms(carried, platforms.Default())(ctx, desc)
		if err != nil {
			return nil, err
		}
		for _, c := range children {
			if size, ok := blobs[c.Digest]; !ok || size != c.Size {
				return nil, fmt.Errorf("the build's image names %s (size %d), which its archive does not carry", c.Digest, c.Size)
			}
			// An index's entries are read whole next (here and by the
			// unpack), as manifests or indexes.
			if isIndexType(desc.MediaType) {
				if !isIndexType(c.MediaType) && !isManifestType(c.MediaType) {
					return nil, fmt.Errorf("the build's image index names %s as %.64q, not a manifest or index", c.Digest, c.MediaType)
				}
				if err := checkReadWholeSize("an index entry", c); err != nil {
					return nil, err
				}
			}
		}
		return children, nil
	}
	if err := images.WalkNotEmpty(ctx, images.SetChildrenLabels(cs, walk), target); err != nil {
		return fmt.Errorf("build import: %w", err)
	}
	return nil
}

// buildChildren is images.Children with the checks a place in the image
// needs. An index's or a manifest's own size was checked where it was named
// (buildArchiveTarget, or its parent's walk), before this reads it whole. A
// manifest's config must be an image config, small, since the unpack reads
// it whole; its layers must be layers, since the unpack streams them as
// such. Configs and layers have no children.
func buildChildren(ctx context.Context, cs content.Provider, desc ocispec.Descriptor) ([]ocispec.Descriptor, error) {
	switch {
	case isIndexType(desc.MediaType):
		return images.Children(ctx, cs, desc)
	case isManifestType(desc.MediaType):
		raw, err := content.ReadBlob(ctx, cs, desc)
		if err != nil {
			return nil, err
		}
		var m ocispec.Manifest
		if err := json.Unmarshal(raw, &m); err != nil {
			return nil, fmt.Errorf("the build's manifest %s: %w", desc.Digest, err)
		}
		if m.Config.MediaType != ocispec.MediaTypeImageConfig && m.Config.MediaType != images.MediaTypeDockerSchema2Config {
			return nil, fmt.Errorf("the build's manifest %s names its config %s as %.64q, not an image config", desc.Digest, m.Config.Digest, m.Config.MediaType)
		}
		if err := checkReadWholeSize("a config", m.Config); err != nil {
			return nil, err
		}
		for _, l := range m.Layers {
			if !images.IsLayerType(l.MediaType) {
				return nil, fmt.Errorf("the build's manifest %s names %s as a layer of type %.64q, not a layer type", desc.Digest, l.Digest, l.MediaType)
			}
		}
		return append([]ocispec.Descriptor{m.Config}, m.Layers...), nil
	}
	return nil, nil
}

func isIndexType(mt string) bool {
	return mt == ocispec.MediaTypeImageIndex || mt == images.MediaTypeDockerSchema2ManifestList
}

func isManifestType(mt string) bool {
	return mt == ocispec.MediaTypeImageManifest || mt == images.MediaTypeDockerSchema2Manifest
}

// checkReadWholeSize refuses a blob read whole into memory (the place it
// holds: the image, an index entry, a config) over maxBuildManifestBytes.
func checkReadWholeSize(place string, desc ocispec.Descriptor) error {
	if desc.Size <= maxBuildManifestBytes {
		return nil
	}
	return fmt.Errorf("the build's image names %s, %s, of %d bytes, more than the %d a manifest, index or config may be",
		desc.Digest, place, desc.Size, maxBuildManifestBytes)
}

// isSparse reports whether a tar header describes a sparse file, in GNU's
// old format or as PAX GNU.sparse.* records.
func isSparse(hdr *tar.Header) bool {
	if hdr.Typeflag == tar.TypeGNUSparse {
		return true
	}
	for k := range hdr.PAXRecords {
		if strings.HasPrefix(k, "GNU.sparse.") {
			return true
		}
	}
	return false
}

// blobDigest is the sha256 digest a blob's file name in the archive
// carries: exactly 64 lowercase hex digits.
func blobDigest(encoded string) (digest.Digest, error) {
	if len(encoded) != 64 || strings.ToLower(encoded) != encoded {
		return "", fmt.Errorf("the build's image archive has a blob named %.80q, want 64 lowercase hex digits", encoded)
	}
	if _, err := hex.DecodeString(encoded); err != nil {
		return "", fmt.Errorf("the build's image archive has a blob named %.80q, want 64 lowercase hex digits", encoded)
	}
	return digest.NewDigestFromEncoded(digest.SHA256, encoded), nil
}

// writeBuildBlob writes one blob of size bytes from r into cs under dgst.
// Its bytes are hashed here as they are read, whether or not containerd
// already has that content (WriteBlob stops reading when it does): a blob
// whose bytes do not match its name fails the import.
func writeBuildBlob(ctx context.Context, cs content.Ingester, r io.Reader, dgst digest.Digest, size int64) error {
	h := dgst.Algorithm().Digester()
	tee := io.TeeReader(r, h.Hash())
	desc := ocispec.Descriptor{Digest: dgst, Size: size}
	if err := content.WriteBlob(ctx, cs, "aerolvm-build-"+dgst.Encoded(), tee, desc); err != nil {
		return fmt.Errorf("build import: write blob %s: %w", dgst, err)
	}
	// What WriteBlob left unread: all of it when the content was already
	// there, none otherwise.
	if _, err := io.Copy(io.Discard, tee); err != nil {
		return fmt.Errorf("build import: read blob %s: %w", dgst, err)
	}
	if h.Digest() != dgst {
		return fmt.Errorf("the build's image archive carries blob %s with other bytes", dgst)
	}
	return nil
}

// readCapped reads one small file of size bytes, refusing one over limit.
func readCapped(r io.Reader, size, limit int64, name string) ([]byte, error) {
	if size < 0 || size > limit {
		return nil, fmt.Errorf("the build's image archive file %s is %d bytes, more than %d", name, size, limit)
	}
	b, err := io.ReadAll(io.LimitReader(r, size))
	if err != nil {
		return nil, fmt.Errorf("the build's image archive file %s: %w", name, err)
	}
	return b, nil
}

// boundedReader passes through at most left bytes and fails, rather than
// end, when the stream holds more: an archive that stops exactly at the
// bound is whole.
type boundedReader struct {
	r    io.Reader
	left int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.left <= 0 {
		var one [1]byte
		n, err := io.ReadFull(b.r, one[:])
		if n > 0 {
			return 0, errBuildArchiveTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > b.left {
		p = p[:b.left]
	}
	n, err := b.r.Read(p)
	b.left -= int64(n)
	return n, err
}
