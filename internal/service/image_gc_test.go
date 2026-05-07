package service

import (
	"testing"

	"github.com/aerol-ai/microvm/pkg/models"
)

func TestImageStillReferenced(t *testing.T) {
	cases := []struct {
		name      string
		sandboxes []*models.Sandbox
		image     string
		want      bool
	}{
		{
			name:      "empty store",
			sandboxes: nil,
			image:     "alpine:latest",
			want:      false,
		},
		{
			name: "all destroyed",
			sandboxes: []*models.Sandbox{
				{Image: "alpine:latest", Status: models.SandboxStatusDestroyed},
				{Image: "alpine:latest", Status: models.SandboxStatusDestroyed},
			},
			image: "alpine:latest",
			want:  false,
		},
		{
			name: "one stopped holds the image",
			sandboxes: []*models.Sandbox{
				{Image: "alpine:latest", Status: models.SandboxStatusDestroyed},
				{Image: "alpine:latest", Status: models.SandboxStatusStopped},
			},
			image: "alpine:latest",
			want:  true,
		},
		{
			name: "one started holds the image",
			sandboxes: []*models.Sandbox{
				{Image: "alpine:latest", Status: models.SandboxStatusStarted},
			},
			image: "alpine:latest",
			want:  true,
		},
		{
			name: "creating counts as a reference",
			sandboxes: []*models.Sandbox{
				{Image: "alpine:latest", Status: models.SandboxStatusCreating},
			},
			image: "alpine:latest",
			want:  true,
		},
		{
			name: "error counts as a reference",
			sandboxes: []*models.Sandbox{
				{Image: "alpine:latest", Status: models.SandboxStatusError},
			},
			image: "alpine:latest",
			want:  true,
		},
		{
			name: "different image is not a reference",
			sandboxes: []*models.Sandbox{
				{Image: "ubuntu:22.04", Status: models.SandboxStatusStarted},
				{Image: "alpine:latest", Status: models.SandboxStatusDestroyed},
			},
			image: "alpine:latest",
			want:  false,
		},
		{
			name: "tag mismatch is not a reference",
			sandboxes: []*models.Sandbox{
				// "alpine" and "alpine:latest" are stored as different strings
				// even if they resolve to the same image — match is exact.
				{Image: "alpine", Status: models.SandboxStatusStarted},
			},
			image: "alpine:latest",
			want:  false,
		},
		{
			name: "empty image string conservatively keeps",
			sandboxes: []*models.Sandbox{
				{Image: "alpine:latest", Status: models.SandboxStatusDestroyed},
			},
			image: "",
			want:  true,
		},
		{
			name: "nil entry is skipped, not panicked on",
			sandboxes: []*models.Sandbox{
				nil,
				{Image: "alpine:latest", Status: models.SandboxStatusDestroyed},
			},
			image: "alpine:latest",
			want:  false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := imageStillReferenced(tc.sandboxes, tc.image); got != tc.want {
				t.Fatalf("imageStillReferenced(..., %q) = %v, want %v", tc.image, got, tc.want)
			}
		})
	}
}
