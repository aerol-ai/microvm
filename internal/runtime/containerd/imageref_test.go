package containerd

import (
	"context"
	"errors"
	"testing"

	cntr "github.com/containerd/containerd"
)

// TestEnsureImageNormalizesShortRef is the regression for the live pull failure
// `parse "dummy://alpine:3.20": invalid port ":3.20"`: containerd's resolver
// cannot handle a bare docker ref, so ensureImage must normalize it to a
// fully-qualified name (as `ctr` does) before GetImage/Pull.
func TestEnsureImageNormalizesShortRef(t *testing.T) {
	d := newTestDriver(t)
	tr := newFakeTransport()
	var pulledRef string
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) {
		return nil, errors.New("not present")
	}
	tr.pullImageFn = func(_ context.Context, ref string, _ ...cntr.RemoteOpt) (cntr.Image, error) {
		pulledRef = ref
		return &fakeImage{name: ref}, nil
	}
	d.SetClient(NewTestClient("aerolvm", tr))

	if _, err := d.ensureImage(context.Background(), d.client, "alpine:3.20", nil); err != nil {
		t.Fatalf("ensureImage: %v", err)
	}
	if pulledRef != "docker.io/library/alpine:3.20" {
		t.Fatalf("pull ref = %q, want normalized docker.io/library/alpine:3.20", pulledRef)
	}
}

func TestEnsureImageKeepsFullyQualifiedRef(t *testing.T) {
	d := newTestDriver(t)
	tr := newFakeTransport()
	var pulledRef string
	tr.getImageFn = func(context.Context, string) (cntr.Image, error) {
		return nil, errors.New("not present")
	}
	tr.pullImageFn = func(_ context.Context, ref string, _ ...cntr.RemoteOpt) (cntr.Image, error) {
		pulledRef = ref
		return &fakeImage{name: ref}, nil
	}
	d.SetClient(NewTestClient("aerolvm", tr))

	const full = "aocr.example.com/team/img:v1"
	if _, err := d.ensureImage(context.Background(), d.client, full, nil); err != nil {
		t.Fatalf("ensureImage: %v", err)
	}
	if pulledRef != full {
		t.Fatalf("pull ref = %q, want unchanged %q", pulledRef, full)
	}
}
