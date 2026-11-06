package containerd

import (
	"context"
	"errors"
	"slices"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
)

// TestPoolImageID (W3): the warm pool's image-change check finds an image
// under the same local names a create tries before it pulls, returns the
// digest parkContainer records, and never pulls.
func TestPoolImageID(t *testing.T) {
	stored := &fakeImage{name: "docker.io/library/python:3.12", target: ocispec.Descriptor{Digest: digest.FromString("v2")}}
	for _, tc := range []struct {
		name  string
		ref   string
		have  string
		tried []string
		ok    bool
	}{
		{"exact local name", "python:3.12", "python:3.12", []string{"python:3.12"}, true},
		{"a tagless local name gets :latest", "snap", "snap:latest", []string{"snap", "snap:latest"}, true},
		{"the registry-normalized name", "python:3.12", "docker.io/library/python:3.12", []string{"python:3.12", "docker.io/library/python:3.12"}, true},
		{"missing everywhere", "python:3.12", "", []string{"python:3.12", "docker.io/library/python:3.12"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ft := newFakeTransport()
			var tried []string
			ft.getImageFn = func(_ context.Context, ref string) (cntr.Image, error) {
				tried = append(tried, ref)
				if ref == tc.have {
					return stored, nil
				}
				return nil, errdefs.ErrNotFound
			}
			ft.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) {
				t.Fatal("the image check must never pull")
				return nil, nil
			}
			d := newTestDriver(t)
			d.SetClient(NewTestClient("aerolvm", ft))
			id, err := d.PoolImageID(context.Background(), tc.ref)
			if !slices.Equal(tried, tc.tried) {
				t.Fatalf("looked up %v, want %v", tried, tc.tried)
			}
			if tc.ok {
				if err != nil || id != digest.FromString("v2").String() {
					t.Fatalf("PoolImageID = %q %v", id, err)
				}
				return
			}
			if err == nil || !errors.Is(err, errdefs.ErrNotFound) || id != "" {
				t.Fatalf("missing = %q %v, want a not-found error", id, err)
			}
		})
	}
}
