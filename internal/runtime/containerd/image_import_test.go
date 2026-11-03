package containerd

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// A Firecracker snapshot lands in this engine as a one-layer image beside
// its own commits, so the registry pusher, delete and GC treat both alike.

func importFixture(t *testing.T) (*Driver, *fakeSnapshotBackend) {
	t.Helper()
	d := newTestDriver(t)
	backend := &fakeSnapshotBackend{}
	testSnapshotBackend = backend
	t.Cleanup(func() { testSnapshotBackend = nil })
	return d, backend
}

func TestImportRootfsImageBuildsAOneLayerImage(t *testing.T) {
	d, backend := importFixture(t)
	rootfs := []byte("a tar stream of the VM's files")
	id, err := d.ImportRootfsImage(context.Background(), "aerolvm-snapshot/abc", bytes.NewReader(rootfs))
	if err != nil {
		t.Fatalf("ImportRootfsImage: %v", err)
	}
	img := backend.createdArg
	if img.Name != "aerolvm-snapshot/abc:latest" {
		t.Fatalf("image name = %q, want the tagged ref", img.Name)
	}
	if id != img.Target.Digest.String() || img.Target.MediaType != ocispec.MediaTypeImageManifest {
		t.Fatalf("id %q target %+v, want the manifest digest", id, img.Target)
	}
	if !backend.unpacked {
		t.Fatal("the image was not unpacked; a container create from it would not find its layers")
	}
	// The layer is the input, gzipped.
	gz, err := gzip.NewReader(bytes.NewReader(backend.layerData))
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(gz); !bytes.Equal(got, rootfs) {
		t.Fatalf("layer content = %q, want the rootfs tar", got)
	}
	var manifest ocispec.Manifest
	if err := json.Unmarshal(backend.blobData[img.Target.Digest.String()], &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.Layers) != 1 || manifest.Layers[0].MediaType != ocispec.MediaTypeImageLayerGzip ||
		manifest.Layers[0].Digest != digest.FromBytes(backend.layerData) {
		t.Fatalf("manifest layers = %+v", manifest.Layers)
	}
	labels := backend.blobLabels[img.Target.Digest.String()]
	if labels["containerd.io/gc.ref.content.config"] != manifest.Config.Digest.String() ||
		labels["containerd.io/gc.ref.content.l.0"] != manifest.Layers[0].Digest.String() {
		t.Fatalf("manifest gc labels = %v: GC would collect the config or layer", labels)
	}
	var config ocispec.Image
	if err := json.Unmarshal(backend.blobData[manifest.Config.Digest.String()], &config); err != nil {
		t.Fatal(err)
	}
	if len(config.RootFS.DiffIDs) != 1 || config.RootFS.DiffIDs[0] != digest.FromBytes(rootfs) {
		t.Fatalf("diff_ids = %v, want the uncompressed digest %s", config.RootFS.DiffIDs, digest.FromBytes(rootfs))
	}
	if config.OS != "linux" || config.Architecture == "" {
		t.Fatalf("config platform = %s/%s", config.OS, config.Architecture)
	}
}

// A second snapshot under the same name repoints the image.
func TestImportRootfsImageRepointsAnExistingName(t *testing.T) {
	d, backend := importFixture(t)
	backend.createErr = errdefs.ErrAlreadyExists
	id, err := d.ImportRootfsImage(context.Background(), "aerolvm-snapshot/abc:latest", strings.NewReader("v2"))
	if err != nil {
		t.Fatalf("ImportRootfsImage over an existing name: %v", err)
	}
	if backend.updated.Name != "aerolvm-snapshot/abc:latest" || id != backend.updated.Target.Digest.String() {
		t.Fatalf("updated %+v, id %q", backend.updated, id)
	}
}

func TestImportRootfsImageErrors(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name string
		ref  string
		set  func(*fakeSnapshotBackend)
		want string
	}{
		{"a digest ref", "aerolvm-snapshot/abc@sha256:1", nil, "digest"},
		{"layer", "s:1", func(b *fakeSnapshotBackend) { b.writeLayerErr = boom }, "import layer"},
		{"config blob", "s:1", func(b *fakeSnapshotBackend) { b.writeBlobErr = boom }, "boom"},
		{"image record", "s:1", func(b *fakeSnapshotBackend) { b.createErr = boom }, "import image record"},
		{"update", "s:1", func(b *fakeSnapshotBackend) { b.createErr = errdefs.ErrAlreadyExists; b.updateErr = boom }, "import image record"},
		{"unpack", "s:1", func(b *fakeSnapshotBackend) { b.unpackErr = boom }, "import unpack"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d, backend := importFixture(t)
			if tc.set != nil {
				tc.set(backend)
			}
			if _, err := d.ImportRootfsImage(context.Background(), tc.ref, strings.NewReader("x")); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestGzipLayer(t *testing.T) {
	w := &memLayerWriter{}
	desc, diffID, err := gzipLayer(context.Background(), w, strings.NewReader("files"))
	if err != nil || desc.Size != int64(w.buf.Len()) || diffID != digest.FromString("files") {
		t.Fatalf("desc %+v diff %s err %v", desc, diffID, err)
	}
	// An identical layer already in the store is fine.
	if _, _, err := gzipLayer(context.Background(), &memLayerWriter{commitErr: errdefs.ErrAlreadyExists}, strings.NewReader("x")); err != nil {
		t.Fatalf("already-exists commit: %v", err)
	}
	if _, _, err := gzipLayer(context.Background(), &memLayerWriter{commitErr: errors.New("disk full")}, strings.NewReader("x")); err == nil || !strings.Contains(err.Error(), "commit layer") {
		t.Fatalf("failed commit: %v", err)
	}
	if _, _, err := gzipLayer(context.Background(), &memLayerWriter{}, &failingReader{}); err == nil || !strings.Contains(err.Error(), "compress layer") {
		t.Fatalf("failed read: %v", err)
	}
	// The store fails once the 10-byte gzip header is in: the input is
	// small enough to sit in the compressor, so the final flush is what fails.
	if _, _, err := gzipLayer(context.Background(), &shortLayerWriter{room: 10}, strings.NewReader("x")); err == nil || !strings.Contains(err.Error(), "compress layer") {
		t.Fatalf("failed flush: %v", err)
	}
}

// shortLayerWriter takes room bytes, then reports the store full.
type shortLayerWriter struct {
	memLayerWriter
	room int
}

func (s *shortLayerWriter) Write(p []byte) (int, error) {
	if s.buf.Len()+len(p) > s.room {
		return 0, errors.New("store full")
	}
	return s.memLayerWriter.Write(p)
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }

func TestExportImageArchive(t *testing.T) {
	d, backend := importFixture(t)
	backend.getImg = images.Image{Name: "aerolvm-snapshot/abc:latest"}
	var buf bytes.Buffer
	ok, err := d.ExportImageArchive(context.Background(), "aerolvm-snapshot/abc", &buf)
	if err != nil || !ok || backend.exported != "aerolvm-snapshot/abc:latest" || buf.String() != "oci-archive:aerolvm-snapshot/abc:latest" {
		t.Fatalf("ok %v err %v exported %q wrote %q", ok, err, backend.exported, buf.String())
	}

	backend.getErr = errdefs.ErrNotFound
	if ok, err := d.ExportImageArchive(context.Background(), "aerolvm-snapshot/abc", io.Discard); ok || err != nil {
		t.Fatalf("missing image: ok %v err %v, want false, nil", ok, err)
	}
	backend.getErr = errors.New("store down")
	if _, err := d.ExportImageArchive(context.Background(), "aerolvm-snapshot/abc", io.Discard); err == nil {
		t.Fatal("a store error was swallowed")
	}
	backend.getErr, backend.exportErr = nil, errors.New("write failed")
	if _, err := d.ExportImageArchive(context.Background(), "aerolvm-snapshot/abc", io.Discard); err == nil || !strings.Contains(err.Error(), "export image") {
		t.Fatalf("export error: %v", err)
	}
	if _, err := d.ExportImageArchive(context.Background(), "x@sha256:1", io.Discard); err == nil {
		t.Fatal("a digest ref was accepted")
	}
}

// Without a live containerd the raw backend refuses instead of panicking.
func TestRawBackendImportMethodsNeedLiveContainerd(t *testing.T) {
	d := newTestDriver(t)
	b := &rawSnapshotBackend{d: d, client: d.client}
	if _, _, err := b.writeLayer(context.Background(), "r", strings.NewReader("x")); err == nil {
		t.Error("writeLayer without containerd succeeded")
	}
	if _, err := b.updateImage(context.Background(), images.Image{}); err == nil {
		t.Error("updateImage without containerd succeeded")
	}
	if err := b.exportImage(context.Background(), "r", io.Discard); err == nil {
		t.Error("exportImage without containerd succeeded")
	}
}

func TestImportRootfsImageFailsWhenTheManifestCannotBeWritten(t *testing.T) {
	d, backend := importFixture(t)
	backend.writeBlobErr, backend.writeBlobFailAt = errors.New("disk full"), 2
	if _, err := d.ImportRootfsImage(context.Background(), "s:1", strings.NewReader("x")); err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err = %v, want the manifest write error", err)
	}
}

// Without a containerd connection, or with no live client behind it, the
// import and export refuse instead of panicking.
func TestImportAndExportNeedContainerd(t *testing.T) {
	d := newTestDriver(t) // a client with no live containerd, and no test backend
	if _, err := d.ImportRootfsImage(context.Background(), "s:1", strings.NewReader("x")); err == nil || !strings.Contains(err.Error(), "requires live containerd") {
		t.Fatalf("import: %v", err)
	}
	if _, err := d.ExportImageArchive(context.Background(), "s:1", io.Discard); err == nil || !strings.Contains(err.Error(), "requires live containerd") {
		t.Fatalf("export: %v", err)
	}
	orig := connectFn
	t.Cleanup(func() { connectFn = orig })
	connectFn = func(string, string) (*Client, error) { return nil, errors.New("no socket") }
	unconnected := New(Config{}, nil, nil)
	if _, err := unconnected.ImportRootfsImage(context.Background(), "s:1", strings.NewReader("x")); err == nil || !strings.Contains(err.Error(), "no socket") {
		t.Fatalf("import without a connection: %v", err)
	}
	if _, err := unconnected.ExportImageArchive(context.Background(), "s:1", io.Discard); err == nil || !strings.Contains(err.Error(), "no socket") {
		t.Fatalf("export without a connection: %v", err)
	}
}

// layerStore is a content.Store whose Writer is an in-memory one; the other
// methods are never called by writeLayer.
type layerStore struct {
	content.Store
	w       *contentWriter
	openErr error
}

func (s *layerStore) Writer(context.Context, ...content.WriterOpt) (content.Writer, error) {
	if s.openErr != nil {
		return nil, s.openErr
	}
	return s.w, nil
}

type contentWriter struct {
	memLayerWriter
	closed bool
}

func (w *contentWriter) Close() error                    { w.closed = true; return nil }
func (w *contentWriter) Status() (content.Status, error) { return content.Status{}, nil }
func (w *contentWriter) Truncate(int64) error            { return nil }
func (w *contentWriter) Commit(ctx context.Context, size int64, expected digest.Digest, opts ...content.Opt) error {
	return w.memLayerWriter.Commit(ctx, size, expected, opts...)
}

func TestRawBackendWriteLayerStreamsIntoTheContentStore(t *testing.T) {
	d := newTestDriver(t)
	store := &layerStore{w: &contentWriter{}}
	orig := snapshotContentStoreFn
	t.Cleanup(func() { snapshotContentStoreFn = orig })
	snapshotContentStoreFn = func(*Client) content.Store { return store }

	b := &rawSnapshotBackend{d: d, client: d.client}
	desc, diffID, err := b.writeLayer(context.Background(), "aerolvm-snapshot/abc:latest", strings.NewReader("files"))
	if err != nil || diffID != digest.FromString("files") || desc.Size != int64(store.w.buf.Len()) || !store.w.closed {
		t.Fatalf("desc %+v diff %s err %v closed %v", desc, diffID, err, store.w.closed)
	}
	store.openErr = errors.New("locked")
	if _, _, err := b.writeLayer(context.Background(), "r", strings.NewReader("x")); err == nil {
		t.Fatal("a writer that cannot open gave no error")
	}
}

// The layer has no gc reference until the image's labels land, so the
// import holds a lease for its whole length and gives it back after.
func TestImportRootfsImageHoldsALeaseUntilTheImageIsLabelled(t *testing.T) {
	d, _ := importFixture(t)
	lm := &fakeLeaseManager{}
	orig := leasesServiceFn
	leasesServiceFn = func(*Client) leaseManager { return lm }
	t.Cleanup(func() { leasesServiceFn = orig })
	if _, err := d.ImportRootfsImage(context.Background(), "aerolvm-snapshot/abc", bytes.NewReader([]byte("tar"))); err != nil {
		t.Fatalf("ImportRootfsImage: %v", err)
	}
	if len(lm.created) != 1 || len(lm.deleted) != 1 || lm.created[0] != lm.deleted[0] {
		t.Fatalf("leases created %v deleted %v, want one taken and given back", lm.created, lm.deleted)
	}

	lm = &fakeLeaseManager{createErr: errors.New("lease service down")}
	if _, err := d.ImportRootfsImage(context.Background(), "aerolvm-snapshot/abc", bytes.NewReader([]byte("tar"))); err == nil || !strings.Contains(err.Error(), "import lease") {
		t.Fatalf("err = %v, want the lease error", err)
	}
}
