package containerd

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// TestPushSourceCandidatesLatestFallback locks in the snapshot-push fix: a
// tagless source (the bare snapshot name the reconciler passes) must fall back
// to "<name>:latest", because CreateSnapshot commits the local image as
// "<name>:latest". Without the fallback, livePush's exact-match GetImage failed
// "image not found", the snapshot never reached AOCR, and cross-node
// create-from-snapshot broke (UC-21). An already-tagged/digested ref is used
// as-is so we never invent a spurious ":latest" candidate.
func TestPushSourceCandidatesLatestFallback(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   []string
	}{
		{
			name:   "tagless snapshot name falls back to :latest",
			source: "cluster-x-testsnap-1700000000-snap",
			want:   []string{"cluster-x-testsnap-1700000000-snap", "cluster-x-testsnap-1700000000-snap:latest"},
		},
		{
			name:   "already-tagged ref used as-is",
			source: "cluster-x-testsnap-1700000000-snap:latest",
			want:   []string{"cluster-x-testsnap-1700000000-snap:latest"},
		},
		{
			name:   "versioned tag used as-is",
			source: "repo/app:v1",
			want:   []string{"repo/app:v1"},
		},
		{
			// The registry host:port colon must NOT be mistaken for a tag, so a
			// tagless AOCR-style repo still gets the :latest fallback.
			source: "aocr.aerol.ai:443/cluster/prod/snapshots/s-snap",
			name:   "registry host:port with tagless repo still falls back",
			want:   []string{"aocr.aerol.ai:443/cluster/prod/snapshots/s-snap", "aocr.aerol.ai:443/cluster/prod/snapshots/s-snap:latest"},
		},
		{
			name:   "digest ref used as-is",
			source: "repo/app@sha256:abc123",
			want:   []string{"repo/app@sha256:abc123"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := pushSourceCandidates(tc.source)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("pushSourceCandidates(%q) = %v, want %v", tc.source, got, tc.want)
			}
		})
	}
}

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
