package docker

import (
	"context"
	"strings"
	"testing"
)

// Docker's /images/create pulls every tag of a repository when fromImage
// names none. A create with an untagged image must ask for :latest, as the
// docker CLI does, or it pulls the whole repository (live: hundreds of
// gcr.io/distroless/static-debian12 tags, until the create timed out).
func TestPullImageNamesATag(t *testing.T) {
	digest := "ghcr.io/aerol-ai/sandbox@sha256:" + strings.Repeat("a", 64)
	for _, tc := range []struct {
		ref, want string
	}{
		{"gcr.io/distroless/static-debian12", "gcr.io/distroless/static-debian12:latest"},
		{"ubuntu", "ubuntu:latest"},
		{"localhost:5000/team/app", "localhost:5000/team/app:latest"}, // the port is not a tag
		{"alpine:3.20", "alpine:3.20"},
		{"localhost:5000/team/app:v2", "localhost:5000/team/app:v2"},
		{digest, digest},
		{"Not A Reference", "Not A Reference"}, // left for Docker to reject
	} {
		cap := newCaptureClient(MirrorConfig{}, nil)
		if err := cap.client.pullImage(context.Background(), tc.ref, nil); err != nil {
			t.Fatalf("pullImage(%q): %v", tc.ref, err)
		}
		if cap.from() != tc.want {
			t.Errorf("pullImage(%q) fromImage = %q, want %q", tc.ref, cap.from(), tc.want)
		}
	}
}

// The mirror rewrite sees the tagged reference too, so a mirrored pull of an
// untagged image also asks for one tag.
func TestPullImageNamesATagThroughTheMirror(t *testing.T) {
	cap := newCaptureClient(defaultMirrorCfg(), nil)
	if err := cap.client.pullImage(context.Background(), "ghcr.io/aerol-ai/sandbox", nil); err != nil {
		t.Fatalf("pullImage: %v", err)
	}
	if want := "mirror.aocr.aerol.ai/aocr/ghcr/aerol-ai/sandbox:latest"; cap.from() != want {
		t.Fatalf("fromImage = %q, want %q", cap.from(), want)
	}
}
