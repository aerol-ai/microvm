package containerd

import (
	"context"
	"errors"
	"testing"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

func TestRegistryPusherPushImage(t *testing.T) {
	p := NewRegistryPusher(nil)
	p.pushFn = func(ctx context.Context, source, dest string, auth models.RegistryAuth) (string, error) {
		if source != "snap:local" || dest != "aocr.example/c/snapshots/n:latest" {
			t.Fatalf("source/dest = %s %s", source, dest)
		}
		if auth.Username != "cluster" || auth.Password != "pat" {
			t.Fatalf("auth = %+v", auth)
		}
		return "sha256:abc", nil
	}
	var gotDigest string
	ref, err := p.PushImage(context.Background(), docker.PushImageRequest{
		SourceTag: "snap:local",
		DestRef:   "aocr.example/c/snapshots/n:latest",
		Auth:      models.RegistryAuth{Username: "cluster", Password: "pat", Server: "aocr.example"},
		OnDigest:  func(d string) { gotDigest = d },
	})
	if err != nil {
		t.Fatal(err)
	}
	if ref != "aocr.example/c/snapshots/n:latest" {
		t.Fatalf("ref = %q", ref)
	}
	if gotDigest != "sha256:abc" {
		t.Fatalf("digest = %q", gotDigest)
	}
}

func TestRegistryPusherValidation(t *testing.T) {
	p := NewRegistryPusher(nil)
	p.pushFn = func(context.Context, string, string, models.RegistryAuth) (string, error) {
		return "", errors.New("should not run")
	}
	if _, err := p.PushImage(context.Background(), docker.PushImageRequest{}); err == nil {
		t.Fatal("want source required")
	}
	if _, err := p.PushImage(context.Background(), docker.PushImageRequest{SourceTag: "a"}); err == nil {
		t.Fatal("want dest required")
	}
	if _, err := p.PushImage(context.Background(), docker.PushImageRequest{SourceTag: "a", DestRef: "b"}); err == nil {
		t.Fatal("want auth required")
	}
	var nilPusher *RegistryPusher
	if _, err := nilPusher.PushImage(context.Background(), docker.PushImageRequest{}); err == nil {
		t.Fatal("want nil pusher error")
	}
}

func TestPushCredScopeHost(t *testing.T) {
	cases := []struct {
		name       string
		dest       string
		authServer string
		want       string
		wantErr    bool
	}{
		{"dest carries host", "aocr.example.com/repo/img:tag", "", "aocr.example.com", false},
		{"dest host beats auth server", "aocr.example.com/r/i:t", "other.example.com", "aocr.example.com", false},
		{"hostless ref falls back to auth server", "myrepo/img", "aocr.example.com", "aocr.example.com", false},
		{"localhost with port", "localhost:5000/img", "", "localhost:5000", false},
		{"no host anywhere refuses", "myrepo/img", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := pushCredScopeHost(tc.dest, tc.authServer)
			if tc.wantErr {
				if err == nil {
					t.Fatal("want error refusing to broadcast credentials")
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("pushCredScopeHost(%q,%q) = (%q,%v), want %q", tc.dest, tc.authServer, got, err, tc.want)
			}
		})
	}
}
