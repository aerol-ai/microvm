package containerd

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// The archive's bounds hold for what it describes, not only for the bytes
// it carries (review of #1397, F1-F3): a sparse entry describes any size
// in a few bytes, a manifest is read whole, and every blob is a containerd
// write.

// rawTarHeader is one ustar header block, written by hand so a test can
// make entries Go's tar writer refuses to.
func rawTarHeader(name string, typ byte, size int64) []byte {
	b := make([]byte, 512)
	copy(b[0:100], name)
	copy(b[100:108], "0000644\x00")
	copy(b[108:116], "0000000\x00")
	copy(b[116:124], "0000000\x00")
	copy(b[124:136], fmt.Sprintf("%011o\x00", size))
	copy(b[136:148], fmt.Sprintf("%011o\x00", 0))
	b[156] = typ
	copy(b[257:263], "ustar\x00")
	copy(b[263:265], "00")
	for i := 148; i < 156; i++ {
		b[i] = ' '
	}
	var sum int64
	for _, c := range b {
		sum += int64(c)
	}
	copy(b[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return b
}

func paxRecord(k, v string) string {
	body := " " + k + "=" + v + "\n"
	n := len(body) + 1
	for {
		s := strconv.Itoa(n) + body
		if len(s) == n {
			return s
		}
		n = len(s)
	}
}

func pad512(b []byte) []byte {
	if r := len(b) % 512; r != 0 {
		b = append(b, make([]byte, 512-r)...)
	}
	return b
}

// sparseEntry is a PAX GNU sparse entry (format 0.1) named name whose
// logical size is size, all one hole: three 512-byte blocks in the archive.
func sparseEntry(name string, size int64) []byte {
	recs := paxRecord("GNU.sparse.major", "0") + paxRecord("GNU.sparse.minor", "1") +
		paxRecord("GNU.sparse.numblocks", "0") + paxRecord("GNU.sparse.map", "") +
		paxRecord("GNU.sparse.size", strconv.FormatInt(size, 10))
	var out []byte
	out = append(out, rawTarHeader("PaxHeaders/x", 'x', int64(len(recs)))...)
	out = append(out, pad512([]byte(recs))...)
	out = append(out, rawTarHeader(name, '0', 0)...)
	return out
}

// zerosDigest is the sha256 of n zero bytes.
func zerosDigest(n int64) digest.Digest {
	h := sha256.New()
	chunk := make([]byte, 1<<20)
	for n > 0 {
		c := min(n, int64(len(chunk)))
		h.Write(chunk[:c])
		n -= c
	}
	return digest.NewDigestFromEncoded(digest.SHA256, hex.EncodeToString(h.Sum(nil)))
}

// A sparse blob whose bytes really are its name's (zeros) would pass the
// digest check; it is refused for being sparse, under any bound, before
// containerd is asked to write anything.
func TestIngestBuildArchiveRefusesSparseEntries(t *testing.T) {
	const logical = 8 << 20
	img := newOCIImage(t)
	zeros := zerosDigest(logical)
	m, _ := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest,
		Config: img.configD, Layers: []ocispec.Descriptor{{MediaType: ocispec.MediaTypeImageLayer, Digest: zeros, Size: logical}}})
	mD := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(m), Size: int64(len(m))}
	var buf bytes.Buffer
	buf.Write(sparseEntry("blobs/sha256/"+zeros.Encoded(), logical))
	buf.Write(tarOf(t, []archiveEntry{blobEntry(img.config), blobEntry(m),
		{name: "index.json", typ: tar.TypeReg, body: indexOf(mD)},
		{name: "oci-layout", typ: tar.TypeReg, body: []byte(`{"imageLayoutVersion":"1.0.0"}`)}}))
	for _, bound := range []int64{64 << 10, 1 << 30} {
		d, backend, cs, _ := buildImportFixture(t)
		err := d.ImportBuildArchive(context.Background(), builtTag, bytes.NewReader(buf.Bytes()), bound, nil)
		if err == nil || !strings.Contains(err.Error(), "sparse") {
			t.Fatalf("bound %d: err = %v, want the sparse entry refused", bound, err)
		}
		if backend.createdArg.Name != "" {
			t.Fatalf("bound %d: an image was named", bound)
		}
		if _, err := cs.Info(context.Background(), zeros); err == nil {
			t.Fatalf("bound %d: the sparse blob reached containerd", bound)
		}
		sts, _ := cs.ListStatuses(context.Background())
		for _, s := range sts {
			if s.Offset > 0 {
				t.Fatalf("bound %d: containerd's ingest holds %d bytes of a refused archive", bound, s.Offset)
			}
		}
	}
	// The old GNU sparse type is refused too (it is not a regular file).
	cs := &memIngester{blobs: map[digest.Digest][]byte{}}
	_, _, err := ingestBuildArchive(context.Background(), cs, bytes.NewReader(append(rawTarHeader("blobs/sha256/"+zeros.Encoded(), 'S', 0), make([]byte, 1024)...)), 1<<20)
	if err == nil || len(cs.blobs) != 0 {
		t.Fatalf("an old GNU sparse entry: %v, %d blobs", err, len(cs.blobs))
	}
}

// The bound covers the sizes the entries declare, not only the bytes read:
// one entry that declares more than the bound is refused before its bytes
// are written anywhere.
func TestIngestBuildArchiveBoundsDeclaredSizes(t *testing.T) {
	big := bytes.Repeat([]byte{1}, 48<<10)
	data := tarOf(t, []archiveEntry{blobEntry(big), blobEntry(append(big, 2))})
	cs := &memIngester{blobs: map[digest.Digest][]byte{}}
	_, _, err := ingestBuildArchive(context.Background(), cs, bytes.NewReader(data), 64<<10)
	if err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("err = %v, want the declared sizes over the bound refused", err)
	}
	if len(cs.blobs) != 1 || cs.written != int64(len(big)) {
		t.Fatalf("%d blobs and %d bytes written, want only the first blob's %d: the second is refused by its header, before a byte of it is written",
			len(cs.blobs), cs.written, len(big))
	}
}

// Manifests, indexes and configs are read whole into memory, so each must
// be small (a pull caps manifests at about 4 MiB); a larger one is refused
// by its descriptor's size, before it is read.
func TestImportBuildArchiveCapsSmallBlobs(t *testing.T) {
	img := newOCIImage(t)
	pad := bytes.Repeat([]byte(" "), maxBuildManifestBytes)
	bigManifest := append(append([]byte{}, img.manifest...), pad...) // still valid JSON
	bigManifestD := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(bigManifest), Size: int64(len(bigManifest))}
	bigConfig := append(append([]byte{}, img.config...), pad...)
	bigConfigD := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig, Digest: digest.FromBytes(bigConfig), Size: int64(len(bigConfig))}
	m2, _ := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest,
		Config: bigConfigD, Layers: []ocispec.Descriptor{img.layerD}})
	m2D := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(m2), Size: int64(len(m2))}
	layout := archiveEntry{name: "oci-layout", typ: tar.TypeReg, body: []byte(`{"imageLayoutVersion":"1.0.0"}`)}
	for name, entries := range map[string][]archiveEntry{
		"a manifest": {blobEntry(img.config), blobEntry(img.layer), blobEntry(bigManifest),
			{name: "index.json", typ: tar.TypeReg, body: indexOf(bigManifestD)}, layout},
		"a config": {blobEntry(bigConfig), blobEntry(img.layer), blobEntry(m2),
			{name: "index.json", typ: tar.TypeReg, body: indexOf(m2D)}, layout},
	} {
		t.Run(name, func(t *testing.T) {
			d, backend, _, _ := buildImportFixture(t)
			err := d.ImportBuildArchive(context.Background(), builtTag, bytes.NewReader(tarOf(t, entries)), 1<<30, nil)
			if err == nil || !strings.Contains(err.Error(), "more than") {
				t.Fatalf("err = %v, want the %s over %d bytes refused", err, name, maxBuildManifestBytes)
			}
			if backend.createdArg.Name != "" || backend.unpacked {
				t.Fatal("named or unpacked")
			}
		})
	}
	// At the cap it is fine.
	exact := append(append([]byte{}, img.manifest...), bytes.Repeat([]byte(" "), maxBuildManifestBytes-len(img.manifest))...)
	exactD := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(exact), Size: int64(len(exact))}
	d, backend, _, _ := buildImportFixture(t)
	err := d.ImportBuildArchive(context.Background(), builtTag, bytes.NewReader(tarOf(t, []archiveEntry{blobEntry(img.config), blobEntry(img.layer), blobEntry(exact),
		{name: "index.json", typ: tar.TypeReg, body: indexOf(exactD)}, layout})), 1<<30, nil)
	if err != nil || backend.createdArg.Name != builtTag {
		t.Fatalf("a manifest of exactly %d bytes: %v", maxBuildManifestBytes, err)
	}
}

// The number of entries is capped (containerd's own walk stops at 10,000
// children): each blob is a containerd write, through the gate in split
// mode.
func TestIngestBuildArchiveCapsEntries(t *testing.T) {
	entries := make([]archiveEntry, 0, maxBuildArchiveEntries+1)
	for i := 0; i <= maxBuildArchiveEntries; i++ {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(i))
		entries = append(entries, blobEntry(b))
	}
	cs := &memIngester{blobs: map[digest.Digest][]byte{}}
	_, _, err := ingestBuildArchive(context.Background(), cs, bytes.NewReader(tarOf(t, entries)), 1<<30)
	if err == nil || !strings.Contains(err.Error(), "entries") {
		t.Fatalf("err = %v, want more than %d entries refused", err, maxBuildArchiveEntries)
	}
	if len(cs.blobs) != maxBuildArchiveEntries {
		t.Fatalf("%d blobs written, want the read to stop at the cap (%d)", len(cs.blobs), maxBuildArchiveEntries)
	}
}

// A blob is read whole by its place in the image, whatever its media type
// says (review of #1397, F2b): containerd's unpack reads the manifest's
// config whole (image.RootFS) even when its descriptor calls it a layer,
// and follows an index's entries as manifests. So the config must be a
// config, small; an index's entries must be manifests or indexes, small;
// and a manifest's layers must be layers.
func TestImportBuildArchiveChecksBlobsByTheirPlace(t *testing.T) {
	img := newOCIImage(t)
	layout := archiveEntry{name: "oci-layout", typ: tar.TypeReg, body: []byte(`{"imageLayoutVersion":"1.0.0"}`)}
	big := func(b []byte) []byte { // still valid JSON, one byte over the cap
		return append(append([]byte{}, b...), bytes.Repeat([]byte(" "), maxBuildManifestBytes+1-len(b))...)
	}
	desc := func(mt string, b []byte) ocispec.Descriptor {
		return ocispec.Descriptor{MediaType: mt, Digest: digest.FromBytes(b), Size: int64(len(b))}
	}
	manifest := func(config ocispec.Descriptor, layers ...ocispec.Descriptor) []byte {
		m, _ := json.Marshal(ocispec.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageManifest, Config: config, Layers: layers})
		return m
	}
	archive := func(target ocispec.Descriptor, blobs ...[]byte) []archiveEntry {
		var e []archiveEntry
		for _, b := range blobs {
			e = append(e, blobEntry(b))
		}
		return append(e, archiveEntry{name: "index.json", typ: tar.TypeReg, body: indexOf(target)}, layout)
	}
	p := platforms.DefaultSpec()

	// The reviewer's PoC: the config, past the cap, called a layer.
	bigConfig := big(img.config)
	m1 := manifest(desc(ocispec.MediaTypeImageLayerGzip, bigConfig), img.layerD)
	// A small config that is not an image config at all.
	m2 := manifest(desc("application/vnd.example.not-a-config", img.config), img.layerD)
	// A layer that is not a layer.
	m3 := manifest(img.configD, desc(ocispec.MediaTypeImageConfig, img.layer))
	// An index whose entry for this platform, past the cap, calls itself a
	// layer, and one whose entry is a config.
	bigManifest := big(img.manifest)
	asLayer := desc(ocispec.MediaTypeImageLayerGzip, bigManifest)
	asLayer.Platform = &p
	idx1 := indexOf(asLayer)
	asConfig := desc(ocispec.MediaTypeImageConfig, img.manifest)
	asConfig.Platform = &p
	idx2 := indexOf(asConfig)

	for _, tc := range []struct {
		name    string
		entries []archiveEntry
		want    string
	}{
		{"a config past the cap called a layer", archive(desc(ocispec.MediaTypeImageManifest, m1), bigConfig, img.layer, m1), "config"},
		{"a config that is no image config", archive(desc(ocispec.MediaTypeImageManifest, m2), img.config, img.layer, m2), "config"},
		{"a layer that is no layer", archive(desc(ocispec.MediaTypeImageManifest, m3), img.config, img.layer, m3), "layer"},
		{"an index entry past the cap called a layer", archive(desc(ocispec.MediaTypeImageIndex, idx1), img.config, img.layer, bigManifest, idx1), "index"},
		{"an index entry that is a config", archive(desc(ocispec.MediaTypeImageIndex, idx2), img.config, img.layer, img.manifest, idx2), "index"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, backend, _, _ := buildImportFixture(t)
			err := d.ImportBuildArchive(context.Background(), builtTag, bytes.NewReader(tarOf(t, tc.entries)), 1<<30, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it refused naming the %s", err, tc.want)
			}
			if backend.createdArg.Name != "" || backend.unpacked {
				t.Fatal("named or unpacked")
			}
		})
	}
	// Docker's media types are the same places: an image in Docker's
	// format still imports.
	dm, _ := json.Marshal(struct {
		SchemaVersion int                  `json:"schemaVersion"`
		MediaType     string               `json:"mediaType"`
		Config        ocispec.Descriptor   `json:"config"`
		Layers        []ocispec.Descriptor `json:"layers"`
	}{2, images.MediaTypeDockerSchema2Manifest, desc(images.MediaTypeDockerSchema2Config, img.config), []ocispec.Descriptor{desc(images.MediaTypeDockerSchema2LayerGzip, img.layer)}})
	d, backend, _, _ := buildImportFixture(t)
	if err := d.ImportBuildArchive(context.Background(), builtTag, bytes.NewReader(tarOf(t, archive(desc(images.MediaTypeDockerSchema2Manifest, dm), img.config, img.layer, dm))), 1<<30, nil); err != nil || backend.createdArg.Name != builtTag {
		t.Fatalf("a Docker-format image: %v", err)
	}
}
