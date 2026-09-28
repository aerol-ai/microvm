package containerd

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/core/content"
	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/errdefs"
	"github.com/containerd/platforms"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

type memProvider struct {
	blobs map[digest.Digest][]byte
}

func (m *memProvider) ReaderAt(_ context.Context, desc ocispec.Descriptor) (content.ReaderAt, error) {
	b, ok := m.blobs[desc.Digest]
	if !ok {
		return nil, errdefs.ErrNotFound
	}
	return &memReaderAt{data: b}, nil
}

type memReaderAt struct{ data []byte }

func (r *memReaderAt) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(r.data)) {
		return 0, io.EOF
	}
	return copy(p, r.data[off:]), nil
}

func (r *memReaderAt) Size() int64  { return int64(len(r.data)) }
func (r *memReaderAt) Close() error { return nil }

type configFakeImage struct {
	manifestDesc ocispec.Descriptor
	configDesc   ocispec.Descriptor
}

func (c *configFakeImage) Name() string               { return "cfg:test" }
func (c *configFakeImage) Target() ocispec.Descriptor { return c.manifestDesc }
func (c *configFakeImage) Labels() map[string]string  { return nil }
func (c *configFakeImage) Unpack(context.Context, string, ...cntr.UnpackOpt) error {
	return nil
}
func (c *configFakeImage) RootFS(context.Context) ([]digest.Digest, error) { return nil, nil }
func (c *configFakeImage) Size(context.Context) (int64, error)             { return 0, nil }
func (c *configFakeImage) Usage(context.Context, ...cntr.UsageOpt) (int64, error) {
	return 0, nil
}
func (c *configFakeImage) Config(context.Context) (ocispec.Descriptor, error) {
	// Real containerd returns the CONFIG descriptor here (index→manifest→config
	// already resolved), not the manifest.
	return c.configDesc, nil
}
func (c *configFakeImage) IsUnpacked(context.Context, string) (bool, error) { return true, nil }
func (c *configFakeImage) ContentStore() content.Store                      { return nil }
func (c *configFakeImage) Metadata() images.Image                           { return images.Image{Name: "cfg:test"} }
func (c *configFakeImage) Platform() platforms.MatchComparer                { return nil }
func (c *configFakeImage) Spec(context.Context) (ocispec.Image, error)      { return ocispec.Image{}, nil }

func newTestImageProvider(t *testing.T) (*memProvider, *configFakeImage) {
	t.Helper()
	cfgBody, err := json.Marshal(ocispec.Image{
		Config: ocispec.ImageConfig{
			Entrypoint: []string{"/entry"},
			Cmd:        []string{"sleep", "inf"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	cfgDigest := digest.FromBytes(cfgBody)
	manifestBody, err := json.Marshal(ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config: ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageConfig,
			Digest:    cfgDigest,
			Size:      int64(len(cfgBody)),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := digest.FromBytes(manifestBody)
	provider := &memProvider{blobs: map[digest.Digest][]byte{
		cfgDigest:      cfgBody,
		manifestDigest: manifestBody,
	}}
	img := &configFakeImage{
		manifestDesc: ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageManifest,
			Digest:    manifestDigest,
			Size:      int64(len(manifestBody)),
		},
		configDesc: ocispec.Descriptor{
			MediaType: ocispec.MediaTypeImageConfig,
			Digest:    cfgDigest,
			Size:      int64(len(cfgBody)),
		},
	}
	return provider, img
}

func TestImageConfigCommandSuccess(t *testing.T) {
	provider, img := newTestImageProvider(t)
	cmd, err := imageConfigCommand(context.Background(), provider, img)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/entry", "sleep", "inf"}
	if len(cmd) != len(want) {
		t.Fatalf("cmd=%v want=%v", cmd, want)
	}
	for i := range want {
		if cmd[i] != want[i] {
			t.Fatalf("cmd=%v want=%v", cmd, want)
		}
	}
}

func TestImageConfigCommandReaderAtError(t *testing.T) {
	_, img := newTestImageProvider(t)
	_, err := imageConfigCommand(context.Background(), &memProvider{blobs: map[digest.Digest][]byte{}}, img)
	if err == nil {
		t.Fatal("want reader error")
	}
}

func TestImageDefaultCommandViaClient(t *testing.T) {
	provider, img := newTestImageProvider(t)
	tr := newFakeTransport()
	tr.provider = provider
	c := NewTestClient("aerolvm", tr)
	cmd, err := imageDefaultCommand(context.Background(), c, img)
	if err != nil {
		t.Fatal(err)
	}
	if len(cmd) != 3 {
		t.Fatalf("cmd=%v", cmd)
	}
}
