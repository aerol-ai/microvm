package containerd

// The reviewer's proof of concept from the review of #1397 (F2b), kept as
// a regression test: the 4 MiB cap went by media type, and containerd's
// unpack reads a manifest's config whole whatever its media type says. A
// 64 MiB config called a layer was imported and named, and the unpack's
// RootFS read allocated all of it. It must now be refused at import.

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"runtime"
	"testing"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestRegressionConfigDisguisedAsLayer(t *testing.T) {
	const pad = 64 << 20
	img := newOCIImage(t)
	big := append(append([]byte{}, img.config...), bytes.Repeat([]byte(" "), pad)...) // still valid JSON
	cfgD := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromBytes(big), Size: int64(len(big))}
	m, _ := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: cfgD, Layers: []ocispec.Descriptor{img.layerD}})
	mD := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(m), Size: int64(len(m))}
	entries := []archiveEntry{blobEntry(big), blobEntry(img.layer), blobEntry(m),
		{name: "index.json", typ: tar.TypeReg, body: indexOf(mD)},
		{name: "oci-layout", typ: tar.TypeReg, body: []byte(`{"imageLayoutVersion":"1.0.0"}`)}}
	d, backend, cs, _ := buildImportFixture(t)
	err := d.ImportBuildArchive(context.Background(), builtTag, bytes.NewReader(tarOf(t, entries)), 1<<30, nil)
	t.Logf("import of a %d MiB config labelled as a layer: err=%v, named %q", len(big)>>20, err, backend.createdArg.Name)
	if err != nil {
		return
	}
	// What containerd's client unpack (image.getLayers -> RootFS) does next.
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	ids, rerr := (&images.Image{Target: mD}).RootFS(context.Background(), cs, platforms.Default())
	runtime.ReadMemStats(&after)
	t.Logf("unpack's RootFS read: diff ids %d, err %v, allocated %d MiB", len(ids), rerr, (after.TotalAlloc-before.TotalAlloc)>>20)
	t.Errorf("a %d MiB config passed the 4 MiB cap by calling itself a layer", len(big)>>20)
}
