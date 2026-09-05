package containerd

import (
	"context"
	"errors"
	"testing"

	cntr "github.com/containerd/containerd/v2/client"
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

func TestEnsureImageFindsLocalRefBeforeNormalizing(t *testing.T) {
	// A committed snapshot / custom-named local image is stored under the exact
	// ref; it must be found as-is, not normalized to docker.io/... and pulled
	// from Docker Hub (the UC-21 regression).
	d := newTestDriver(t)
	tr := newFakeTransport()
	pulled := false
	tr.getImageFn = func(_ context.Context, ref string) (cntr.Image, error) {
		if ref == "myapp-snap:latest" {
			return &fakeImage{name: ref}, nil
		}
		return nil, errors.New("not present")
	}
	tr.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) {
		pulled = true
		return nil, errors.New("should not pull a local ref")
	}
	d.SetClient(NewTestClient("aerolvm", tr))
	img, err := d.ensureImage(context.Background(), d.client, "myapp-snap:latest", nil)
	if err != nil || img == nil {
		t.Fatalf("ensureImage local ref: img=%v err=%v", img, err)
	}
	if pulled {
		t.Fatal("local snapshot ref must not trigger a Docker Hub pull")
	}
}

func TestEnsureImageFindsTaglessLocalRefViaLatest(t *testing.T) {
	// A snapshot referenced without a tag ("myapp-snap") is stored as
	// "myapp-snap:latest"; containerd needs the exact tag, so it must resolve
	// locally via :latest, not fall through to a Docker Hub pull (UC-21).
	d := newTestDriver(t)
	tr := newFakeTransport()
	pulled := false
	tr.getImageFn = func(_ context.Context, ref string) (cntr.Image, error) {
		if ref == "myapp-snap:latest" {
			return &fakeImage{name: ref}, nil
		}
		return nil, errors.New("not present")
	}
	tr.pullImageFn = func(context.Context, string, ...cntr.RemoteOpt) (cntr.Image, error) {
		pulled = true
		return nil, errors.New("should not pull")
	}
	d.SetClient(NewTestClient("aerolvm", tr))
	img, err := d.ensureImage(context.Background(), d.client, "myapp-snap", nil)
	if err != nil || img == nil {
		t.Fatalf("tagless local ref: img=%v err=%v", img, err)
	}
	if pulled {
		t.Fatal("tagless local snapshot must resolve via :latest, not a pull")
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
