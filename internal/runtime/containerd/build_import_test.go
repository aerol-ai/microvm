package containerd

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"strings"
	"sync"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// memLabels is the label store a local content store needs to keep labels
// (the GC references the import writes).
type memLabels struct {
	mu sync.Mutex
	m  map[digest.Digest]map[string]string
}

func (l *memLabels) Get(d digest.Digest) (map[string]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return maps.Clone(l.m[d]), nil
}

func (l *memLabels) Set(d digest.Digest, labels map[string]string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.m[d] = maps.Clone(labels)
	return nil
}

func (l *memLabels) Update(d digest.Digest, update map[string]string) (map[string]string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	cur := l.m[d]
	if cur == nil {
		cur = map[string]string{}
	}
	for k, v := range update {
		if v == "" {
			delete(cur, k)
		} else {
			cur[k] = v
		}
	}
	l.m[d] = cur
	return maps.Clone(cur), nil
}

// newLabeledStore is a real containerd content store on disk: it checks
// every blob's digest and size at commit, as containerd does.
func newLabeledStore(t testing.TB) content.Store {
	t.Helper()
	cs, err := local.NewLabeledStore(t.TempDir(), &memLabels{m: map[digest.Digest]map[string]string{}})
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// archiveEntry is one entry of a test archive.
type archiveEntry struct {
	name     string
	typ      byte
	body     []byte
	linkname string
}

func tarOf(t testing.TB, entries []archiveEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typ, Mode: 0o444, Size: int64(len(e.body)), Linkname: e.linkname}
		if e.typ != tar.TypeReg {
			hdr.Size = 0
			hdr.Mode = 0o755
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// ociImage is a one-layer image for this host, as BuildKit's OCI exporter
// writes it.
type ociImage struct {
	config, layer, manifest    []byte
	configD, layerD, manifestD ocispec.Descriptor
}

func newOCIImage(t testing.TB) ociImage {
	t.Helper()
	var layerTar bytes.Buffer
	tw := tar.NewWriter(&layerTar)
	_ = tw.WriteHeader(&tar.Header{Name: "hello", Mode: 0o644, Size: 3, Typeflag: tar.TypeReg})
	_, _ = tw.Write([]byte("hi\n"))
	_ = tw.Close()
	var layer bytes.Buffer
	gz := gzip.NewWriter(&layer)
	_, _ = gz.Write(layerTar.Bytes())
	_ = gz.Close()
	p := platforms.DefaultSpec()
	config, _ := json.Marshal(ocispec.Image{
		Platform: ocispec.Platform{OS: p.OS, Architecture: p.Architecture, Variant: p.Variant},
		RootFS:   ocispec.RootFS{Type: "layers", DiffIDs: []digest.Digest{digest.FromBytes(layerTar.Bytes())}},
	})
	img := ociImage{config: config, layer: layer.Bytes()}
	img.configD = ocispec.Descriptor{MediaType: ocispec.MediaTypeImageConfig, Digest: digest.FromBytes(config), Size: int64(len(config))}
	img.layerD = ocispec.Descriptor{MediaType: ocispec.MediaTypeImageLayerGzip, Digest: digest.FromBytes(img.layer), Size: int64(len(img.layer))}
	img.manifest, _ = json.Marshal(ocispec.Manifest{
		Versioned: specs.Versioned{SchemaVersion: 2},
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    img.configD,
		Layers:    []ocispec.Descriptor{img.layerD},
	})
	img.manifestD = ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromBytes(img.manifest), Size: int64(len(img.manifest))}
	return img
}

func blobEntry(b []byte) archiveEntry {
	return archiveEntry{name: "blobs/sha256/" + digest.FromBytes(b).Encoded(), typ: tar.TypeReg, body: b}
}

func indexOf(descs ...ocispec.Descriptor) []byte {
	b, _ := json.Marshal(ocispec.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ocispec.MediaTypeImageIndex, Manifests: descs})
	return b
}

// entries are the image's archive entries in BuildKit's order: folders,
// blobs, index.json (whose one entry carries BuildKit's annotations and
// platform), oci-layout.
func (img ociImage) entries() []archiveEntry {
	named := img.manifestD
	named.Annotations = map[string]string{images.AnnotationImageName: "docker.io/library/other:latest", ocispec.AnnotationCreated: "2026-11-22T00:00:00Z"}
	p := platforms.DefaultSpec()
	named.Platform = &p
	return []archiveEntry{
		{name: "blobs/", typ: tar.TypeDir},
		{name: "blobs/sha256/", typ: tar.TypeDir},
		blobEntry(img.config),
		blobEntry(img.layer),
		blobEntry(img.manifest),
		{name: "index.json", typ: tar.TypeReg, body: indexOf(named)},
		{name: "oci-layout", typ: tar.TypeReg, body: []byte(`{"imageLayoutVersion":"1.0.0"}`)},
	}
}

func (img ociImage) archive(t testing.TB) []byte { return tarOf(t, img.entries()) }

// buildImportFixture is a driver whose image calls land in the fake backend
// and whose content store is a real one on disk.
func buildImportFixture(t *testing.T) (*Driver, *fakeSnapshotBackend, content.Store, *fakeLeaseManager) {
	t.Helper()
	d, backend := importFixture(t)
	cs := newLabeledStore(t)
	origCS, origLeases := snapshotContentStoreFn, leasesServiceFn
	lm := &fakeLeaseManager{}
	snapshotContentStoreFn = func(*Client) content.Store { return cs }
	leasesServiceFn = func(*Client) leaseManager { return lm }
	t.Cleanup(func() { snapshotContentStoreFn, leasesServiceFn = origCS, origLeases })
	return d, backend, cs, lm
}

const builtTag = "aerolvm-build/0123456789abcdef:latest"

func TestImportBuildArchiveNamesTheBuildsTag(t *testing.T) {
	d, backend, cs, lm := buildImportFixture(t)
	img := newOCIImage(t)
	calls := 0
	err := d.ImportBuildArchive(context.Background(), builtTag, bytes.NewReader(img.archive(t)), 1<<20, func() error {
		calls++
		if backend.createdArg.Name != "" {
			t.Fatal("the image was named before the build's process finished")
		}
		return nil
	})
	if err != nil {
		t.Fatalf("ImportBuildArchive: %v", err)
	}
	if calls != 1 {
		t.Fatalf("finished called %d times, want once", calls)
	}
	got := backend.createdArg
	if got.Name != builtTag {
		t.Fatalf("image name %q, want the build's tag, never the archive's own name", got.Name)
	}
	if got.Target.Digest != img.manifestD.Digest || got.Target.MediaType != ocispec.MediaTypeImageManifest ||
		got.Target.Size != img.manifestD.Size || got.Target.Annotations != nil || got.Target.Platform != nil {
		t.Fatalf("target %+v, want the bare manifest descriptor", got.Target)
	}
	if !backend.unpacked {
		t.Fatal("not unpacked: a create from the tag would not find its layers")
	}
	// The manifest keeps its config and layer from the garbage collector.
	info, err := cs.Info(context.Background(), img.manifestD.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if info.Labels["containerd.io/gc.ref.content.config"] != img.configD.Digest.String() ||
		info.Labels["containerd.io/gc.ref.content.l.0"] != img.layerD.Digest.String() {
		t.Fatalf("manifest labels %v, want gc refs to its config and layer", info.Labels)
	}
	for _, b := range [][]byte{img.config, img.layer, img.manifest} {
		got, err := content.ReadBlob(context.Background(), cs, ocispec.Descriptor{Digest: digest.FromBytes(b), Size: int64(len(b))})
		if err != nil || !bytes.Equal(got, b) {
			t.Fatalf("blob %s: %v", digest.FromBytes(b), err)
		}
	}
	if len(lm.created) != 1 || len(lm.deleted) != 1 {
		t.Fatalf("leases created %v deleted %v, want one, released", lm.created, lm.deleted)
	}
}

// An index the build wrote (attestations put the image behind one) is
// imported as the target, its manifest walked for this host's platform.
func TestImportBuildArchiveTakesAnIndex(t *testing.T) {
	d, backend, cs, _ := buildImportFixture(t)
	img := newOCIImage(t)
	p := platforms.DefaultSpec()
	inner := img.manifestD
	inner.Platform = &p
	other := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: digest.FromString("not here"), Size: 8,
		Platform: &ocispec.Platform{OS: "plan9", Architecture: "mips"}}
	nested := indexOf(inner, other)
	nestedD := ocispec.Descriptor{MediaType: ocispec.MediaTypeImageIndex, Digest: digest.FromBytes(nested), Size: int64(len(nested))}
	entries := []archiveEntry{blobEntry(img.config), blobEntry(img.layer), blobEntry(img.manifest), blobEntry(nested),
		{name: "index.json", typ: tar.TypeReg, body: indexOf(nestedD)},
		{name: "oci-layout", typ: tar.TypeReg, body: []byte(`{"imageLayoutVersion":"1.0.0"}`)}}
	if err := d.ImportBuildArchive(context.Background(), builtTag, bytes.NewReader(tarOf(t, entries)), 1<<20, nil); err != nil {
		t.Fatalf("ImportBuildArchive: %v", err)
	}
	if backend.createdArg.Target.Digest != nestedD.Digest {
		t.Fatalf("target %v, want the index", backend.createdArg.Target)
	}
	// The other platform's manifest, absent from the archive, is not this
	// host's, so it is neither required nor kept.
	info, _ := cs.Info(context.Background(), nestedD.Digest)
	if info.Labels["containerd.io/gc.ref.content.m.0"] != inner.Digest.String() || len(info.Labels) != 1 {
		t.Fatalf("index labels %v, want only this host's manifest", info.Labels)
	}
}

func TestImportBuildArchiveRepointsAnExistingTag(t *testing.T) {
	d, backend, _, _ := buildImportFixture(t)
	backend.createErr = errdefs.ErrAlreadyExists
	img := newOCIImage(t)
	if err := d.ImportBuildArchive(context.Background(), builtTag, bytes.NewReader(img.archive(t)), 1<<20, nil); err != nil {
		t.Fatalf("ImportBuildArchive over an existing tag: %v", err)
	}
	if backend.updated.Name != builtTag || backend.updated.Target.Digest != img.manifestD.Digest {
		t.Fatalf("updated %+v", backend.updated)
	}
}

// An archive that stops exactly at the bound is whole; one byte more is not.
func TestImportBuildArchiveBound(t *testing.T) {
	img := newOCIImage(t)
	data := img.archive(t)
	d, _, _, _ := buildImportFixture(t)
	if err := d.ImportBuildArchive(context.Background(), builtTag, bytes.NewReader(data), int64(len(data)), nil); err != nil {
		t.Fatalf("an archive of exactly the bound: %v", err)
	}
	d, backend, _, _ := buildImportFixture(t)
	err := d.ImportBuildArchive(context.Background(), builtTag, bytes.NewReader(data), int64(len(data))-1, nil)
	if !errors.Is(err, errBuildArchiveTooLarge) {
		t.Fatalf("one byte over the bound: %v, want errBuildArchiveTooLarge", err)
	}
	if backend.createdArg.Name != "" {
		t.Fatal("an archive over its bound was named")
	}
}

func TestImportBuildArchiveFailures(t *testing.T) {
	boom := errors.New("boom")
	img := newOCIImage(t)
	cases := []struct {
		name    string
		ref     string
		max     int64
		set     func(*fakeSnapshotBackend, *fakeLeaseManager)
		done    error
		wantErr string
		deleted bool
	}{
		{name: "no tag", ref: " ", max: 1 << 20, wantErr: "image name is required"},
		{name: "no bound", ref: builtTag, max: 0, wantErr: "bound must be positive"},
		{name: "lease", ref: builtTag, max: 1 << 20, set: func(_ *fakeSnapshotBackend, l *fakeLeaseManager) { l.createErr = boom }, wantErr: "lease"},
		{name: "the build process failed", ref: builtTag, max: 1 << 20, done: boom, wantErr: "boom"},
		{name: "image record", ref: builtTag, max: 1 << 20, set: func(b *fakeSnapshotBackend, _ *fakeLeaseManager) { b.createErr = boom }, wantErr: "image record"},
		{name: "repoint", ref: builtTag, max: 1 << 20, set: func(b *fakeSnapshotBackend, _ *fakeLeaseManager) {
			b.createErr = errdefs.ErrAlreadyExists
			b.updateErr = boom
		}, wantErr: "image record"},
		{name: "unpack", ref: builtTag, max: 1 << 20, set: func(b *fakeSnapshotBackend, _ *fakeLeaseManager) { b.unpackErr = boom }, wantErr: "unpack", deleted: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, backend, _, lm := buildImportFixture(t)
			if tc.set != nil {
				tc.set(backend, lm)
			}
			err := d.ImportBuildArchive(context.Background(), tc.ref, bytes.NewReader(img.archive(t)), tc.max, func() error { return tc.done })
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v, want %q", err, tc.wantErr)
			}
			if tc.done != nil && backend.createdArg.Name != "" {
				t.Fatal("a build whose process failed was named")
			}
			if tc.deleted != (len(backend.deleted) == 1 && backend.deleted[0] == builtTag) {
				t.Fatalf("deleted %v, want the record removed: %v", backend.deleted, tc.deleted)
			}
		})
	}
}

func TestImportBuildArchiveNeedsLiveContainerd(t *testing.T) {
	d, _, _, _ := buildImportFixture(t)
	snapshotContentStoreFn = func(*Client) content.Store { return nil }
	if err := d.ImportBuildArchive(context.Background(), builtTag, strings.NewReader(""), 1, nil); err == nil || !strings.Contains(err.Error(), "live containerd") {
		t.Fatalf("err = %v", err)
	}
}

// TestIngestBuildArchiveRefuses is the broken-builder suite: the archive
// comes from the process that ran tenant build steps, and every shape below
// is refused before an image is named.
func TestIngestBuildArchiveRefuses(t *testing.T) {
	img := newOCIImage(t)
	good := img.entries()
	layout := archiveEntry{name: "oci-layout", typ: tar.TypeReg, body: []byte(`{"imageLayoutVersion":"1.0.0"}`)}
	index := func(descs ...ocispec.Descriptor) archiveEntry {
		return archiveEntry{name: "index.json", typ: tar.TypeReg, body: indexOf(descs...)}
	}
	blobs := []archiveEntry{blobEntry(img.config), blobEntry(img.layer), blobEntry(img.manifest)}
	with := func(extra ...archiveEntry) []archiveEntry { return append(append([]archiveEntry{}, good...), extra...) }
	withBlobs := func(extra ...archiveEntry) []archiveEntry {
		return append(append([]archiveEntry{}, blobs...), extra...)
	}
	mismatch := blobEntry(img.layer)
	mismatch.body = []byte("other bytes")
	upper := blobEntry(img.layer)
	upper.name = "blobs/sha256/" + strings.ToUpper(img.layerD.Digest.Encoded())
	sized := img.manifestD
	sized.Size++
	layerAsImage := img.layerD
	noLayer := []archiveEntry{blobEntry(img.config), blobEntry(img.manifest), index(img.manifestD), layout}
	cases := []struct {
		name    string
		entries []archiveEntry
		raw     []byte
		want    string
	}{
		{"a Docker manifest.json", with(archiveEntry{name: "manifest.json", typ: tar.TypeReg, body: []byte("[]")}), nil, "unexpected file"},
		{"a file outside the layout", with(archiveEntry{name: "etc/passwd", typ: tar.TypeReg, body: []byte("x")}), nil, "unexpected file"},
		{"a parent path", with(archiveEntry{name: "../blobs/sha256/x", typ: tar.TypeReg, body: []byte("x")}), nil, "unexpected file"},
		{"a symlink", with(archiveEntry{name: "blobs/sha256/link", typ: tar.TypeSymlink, linkname: "/etc/shadow"}), nil, "not a file or folder"},
		{"a hard link", with(archiveEntry{name: "index2", typ: tar.TypeLink, linkname: "index.json"}), nil, "not a file or folder"},
		{"a device", with(archiveEntry{name: "blobs/dev", typ: tar.TypeChar}), nil, "not a file or folder"},
		{"another folder", with(archiveEntry{name: "tmp/", typ: tar.TypeDir}), nil, "unexpected folder"},
		{"a short blob name", with(archiveEntry{name: "blobs/sha256/abc", typ: tar.TypeReg, body: []byte("x")}), nil, "64 lowercase hex"},
		{"an upper-case blob name", withBlobs(upper, index(img.manifestD), layout), nil, "64 lowercase hex"},
		{"a blob name that is not hex", with(archiveEntry{name: "blobs/sha256/" + strings.Repeat("z", 64), typ: tar.TypeReg, body: []byte("x")}), nil, "64 lowercase hex"},
		{"a blob whose bytes are another's", append([]archiveEntry{blobEntry(img.config), mismatch, blobEntry(img.manifest)}, index(img.manifestD), layout), nil, "blob"},
		{"a blob twice", with(blobEntry(img.layer)), nil, "twice"},
		{"two index files", with(index(img.manifestD)), nil, "two index.json"},
		{"two layout files", with(layout), nil, "two oci-layout"},
		{"no layout file", withBlobs(index(img.manifestD)), nil, "not an OCI image layout"},
		{"no index", withBlobs(layout), nil, "not an OCI image layout"},
		{"an empty stream", nil, []byte{}, "not an OCI image layout"},
		{"not a tar", nil, bytes.Repeat([]byte("not a tar archive "), 64), "read the build's image archive"},
		{"another layout version", withBlobs(index(img.manifestD), archiveEntry{name: "oci-layout", typ: tar.TypeReg, body: []byte(`{"imageLayoutVersion":"2.0.0"}`)}), nil, "layout version"},
		{"a layout file over its cap", withBlobs(index(img.manifestD), archiveEntry{name: "oci-layout", typ: tar.TypeReg, body: bytes.Repeat([]byte(" "), maxBuildLayoutBytes+1)}), nil, "more than"},
		{"an index that is not JSON", withBlobs(archiveEntry{name: "index.json", typ: tar.TypeReg, body: []byte("{")}, layout), nil, "image index"},
		{"an index of no images", withBlobs(index(), layout), nil, "names 0 images"},
		{"an index of two images", withBlobs(index(img.manifestD, img.manifestD), layout), nil, "names 2 images"},
		{"an index of schema 1", withBlobs(archiveEntry{name: "index.json", typ: tar.TypeReg, body: []byte(`{"schemaVersion":1,"manifests":[]}`)}, layout), nil, "schema 1"},
		{"a layer as the image", withBlobs(index(layerAsImage), layout), nil, "want an image manifest or index"},
		{"an image not in the archive", append([]archiveEntry{blobEntry(img.config), blobEntry(img.layer)}, index(img.manifestD), layout), nil, "not in its archive"},
		{"an image at another size", withBlobs(index(sized), layout), nil, "not in its archive"},
		{"an image with a bad digest", withBlobs(index(ocispec.Descriptor{MediaType: ocispec.MediaTypeImageManifest, Digest: "sha512:00", Size: 1}), layout), nil, "not a sha256 digest"},
		{"a layer the archive does not carry", noLayer, nil, "does not carry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, backend, _, _ := buildImportFixture(t)
			data := tc.raw
			if data == nil {
				data = tarOf(t, tc.entries)
			}
			err := d.ImportBuildArchive(context.Background(), builtTag, bytes.NewReader(data), 1<<20, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if backend.createdArg.Name != "" || backend.unpacked {
				t.Fatal("a refused archive was named or unpacked")
			}
		})
	}
}

// A build cannot borrow content the node already holds by naming its
// digest: the archive must carry the bytes, and they are checked even when
// containerd skips the write because it has them.
func TestIngestBuildArchiveChecksBlobsTheStoreHas(t *testing.T) {
	d, backend, cs, _ := buildImportFixture(t)
	img := newOCIImage(t)
	// Another image's layer, already on the node.
	if err := content.WriteBlob(context.Background(), cs, "other", bytes.NewReader(img.layer), img.layerD); err != nil {
		t.Fatal(err)
	}
	forged := blobEntry(img.layer)
	forged.body = bytes.Repeat([]byte{0}, len(img.layer))
	entries := []archiveEntry{blobEntry(img.config), forged, blobEntry(img.manifest),
		{name: "index.json", typ: tar.TypeReg, body: indexOf(img.manifestD)},
		{name: "oci-layout", typ: tar.TypeReg, body: []byte(`{"imageLayoutVersion":"1.0.0"}`)}}
	err := d.ImportBuildArchive(context.Background(), builtTag, bytes.NewReader(tarOf(t, entries)), 1<<20, nil)
	if err == nil || !strings.Contains(err.Error(), "other bytes") {
		t.Fatalf("err = %v, want the forged blob refused", err)
	}
	if backend.createdArg.Name != "" {
		t.Fatal("an image naming content its archive did not carry was named")
	}
	// The same archive with the real bytes imports: content the store
	// already has is fine when the archive carries it too.
	d2, backend2, _, _ := buildImportFixture(t)
	snapshotContentStoreFn = func(*Client) content.Store { return cs }
	if err := d2.ImportBuildArchive(context.Background(), builtTag, bytes.NewReader(img.archive(t)), 1<<20, nil); err != nil {
		t.Fatalf("an archive carrying content the store has: %v", err)
	}
	if backend2.createdArg.Name != builtTag {
		t.Fatalf("named %q", backend2.createdArg.Name)
	}
}

func TestBoundedReader(t *testing.T) {
	for _, tc := range []struct {
		data string
		max  int64
		want string
		err  error
	}{
		{"abc", 3, "abc", nil},
		{"abc", 5, "abc", nil},
		{"abcd", 3, "abc", errBuildArchiveTooLarge},
		{"", 0, "", nil},
		{"a", 0, "", errBuildArchiveTooLarge},
	} {
		got, err := io.ReadAll(&boundedReader{r: strings.NewReader(tc.data), left: tc.max})
		if string(got) != tc.want || !errors.Is(err, tc.err) {
			t.Fatalf("%q bound %d: got %q, %v; want %q, %v", tc.data, tc.max, got, err, tc.want, tc.err)
		}
	}
	if n, err := (&boundedReader{r: strings.NewReader("x"), left: 1}).Read(nil); n != 0 || err != nil {
		t.Fatalf("empty read: %d %v", n, err)
	}
}

// FuzzIngestBuildArchive feeds the archive reader any bytes, as a broken
// builder could. It must never panic, never read past its bound, and
// whatever it accepts must name one image whose blob it wrote, at the size
// and digest the archive claims.
func FuzzIngestBuildArchive(f *testing.F) {
	img := newOCIImage(f)
	f.Add(img.archive(f))
	f.Add(tarOf(f, img.entries()[2:]))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0}, 1024))
	f.Fuzz(func(t *testing.T, data []byte) {
		cs := &memIngester{blobs: map[digest.Digest][]byte{}}
		const bound = 64 << 10
		r := &countingReader{r: bytes.NewReader(data)}
		target, blobs, err := ingestBuildArchive(context.Background(), cs, r, bound)
		if r.n > bound+1 {
			t.Fatalf("read %d bytes past a bound of %d", r.n, bound)
		}
		if err != nil {
			return
		}
		size, ok := blobs[target.Digest]
		if !ok || size != target.Size {
			t.Fatalf("accepted target %v not among the blobs written", target)
		}
		for dgst, size := range blobs {
			b, ok := cs.blobs[dgst]
			if !ok || int64(len(b)) != size || digest.FromBytes(b) != dgst {
				t.Fatalf("blob %s: stored %d bytes, want %d with that digest", dgst, len(b), size)
			}
		}
	})
}

// memIngester is an in-memory content.Ingester that checks a commit's size
// and digest as containerd's store does, for the fuzzer: a store on disk
// per input is too slow to explore with.
type memIngester struct {
	blobs map[digest.Digest][]byte
	// written counts every byte handed to a writer, committed or not.
	written int64
}

func (m *memIngester) Writer(_ context.Context, opts ...content.WriterOpt) (content.Writer, error) {
	var wo content.WriterOpts
	for _, o := range opts {
		if err := o(&wo); err != nil {
			return nil, err
		}
	}
	if _, ok := m.blobs[wo.Desc.Digest]; ok {
		return nil, errdefs.ErrAlreadyExists
	}
	return &memWriter{m: m, ref: wo.Ref}, nil
}

type memWriter struct {
	m   *memIngester
	ref string
	buf bytes.Buffer
}

func (w *memWriter) Write(p []byte) (int, error) {
	w.m.written += int64(len(p))
	return w.buf.Write(p)
}
func (w *memWriter) Close() error          { return nil }
func (w *memWriter) Digest() digest.Digest { return digest.FromBytes(w.buf.Bytes()) }
func (w *memWriter) Truncate(int64) error  { return errors.New("not supported") }
func (w *memWriter) Status() (content.Status, error) {
	return content.Status{Ref: w.ref, Offset: int64(w.buf.Len())}, nil
}

func (w *memWriter) Commit(_ context.Context, size int64, expected digest.Digest, _ ...content.Opt) error {
	if size > 0 && int64(w.buf.Len()) != size {
		return errors.New("unexpected commit size")
	}
	if expected != "" && w.Digest() != expected {
		return errors.New("unexpected commit digest")
	}
	w.m.blobs[w.Digest()] = append([]byte(nil), w.buf.Bytes()...)
	return nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
