package service

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeSnapshotPushDocker captures push calls so tests can assert on the
// rendered destination ref and the registry auth that would have hit
// the Docker daemon. Concurrent-safe because the reconciler tests
// invoke PushOnce from goroutines.
type fakeSnapshotPushDocker struct {
	mu     sync.Mutex
	calls  []docker.PushImageRequest
	result string
	err    error
}

func (f *fakeSnapshotPushDocker) PushImage(_ context.Context, req docker.PushImageRequest) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, req)
	if f.err != nil {
		return "", f.err
	}
	if f.result != "" {
		return f.result, nil
	}
	return req.DestRef, nil
}

func (f *fakeSnapshotPushDocker) lastCall() docker.PushImageRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return docker.PushImageRequest{}
	}
	return f.calls[len(f.calls)-1]
}

func writePATFile(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "pat")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write PAT: %v", err)
	}
	return path
}

func newTestPusher(t *testing.T, patPath string, docker SnapshotPushDocker) *SnapshotPusher {
	t.Helper()
	pusher, err := NewSnapshotPusher(SnapshotPushConfig{
		Enabled:   true,
		Host:      "aocr.test",
		ClusterID: "cluster-42",
		PATPath:   patPath,
	}, docker, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewSnapshotPusher: %v", err)
	}
	return pusher
}

func TestSnapshotPusher_HappyPath(t *testing.T) {
	patPath := writePATFile(t, "secret-token\n")
	fake := &fakeSnapshotPushDocker{}
	pusher := newTestPusher(t, patPath, fake)

	result, err := pusher.PushOnce(context.Background(), &models.SandboxSnapshot{
		Name:  "my-snap",
		Image: "aerolvm-build/abc123:latest",
	})
	if err != nil {
		t.Fatalf("PushOnce: %v", err)
	}

	want := "aocr.test/cluster/cluster-42/snapshots/my-snap:latest"
	if result.RegistryRef != want {
		t.Fatalf("RegistryRef = %q, want %q", result.RegistryRef, want)
	}
	call := fake.lastCall()
	if call.SourceTag != "aerolvm-build/abc123:latest" {
		t.Fatalf("SourceTag = %q", call.SourceTag)
	}
	if call.DestRef != want {
		t.Fatalf("DestRef = %q", call.DestRef)
	}
	if call.Auth.Username != "cluster-42" || call.Auth.Password != "secret-token" {
		t.Fatalf("Auth = %+v", call.Auth)
	}
	if call.Auth.Server != "aocr.test" {
		t.Fatalf("Auth.Server = %q", call.Auth.Server)
	}
}

func TestSnapshotPusher_PATRotation(t *testing.T) {
	patPath := writePATFile(t, "first-token")
	fake := &fakeSnapshotPushDocker{}
	pusher := newTestPusher(t, patPath, fake)

	if _, err := pusher.PushOnce(context.Background(), &models.SandboxSnapshot{
		Name: "a", Image: "img:1",
	}); err != nil {
		t.Fatalf("first PushOnce: %v", err)
	}
	if got := fake.lastCall().Auth.Password; got != "first-token" {
		t.Fatalf("first Password = %q", got)
	}

	if err := os.WriteFile(patPath, []byte("second-token\n"), 0o600); err != nil {
		t.Fatalf("rotate PAT: %v", err)
	}
	if _, err := pusher.PushOnce(context.Background(), &models.SandboxSnapshot{
		Name: "b", Image: "img:2",
	}); err != nil {
		t.Fatalf("second PushOnce: %v", err)
	}
	if got := fake.lastCall().Auth.Password; got != "second-token" {
		t.Fatalf("rotated Password = %q, want second-token", got)
	}
}

func TestSnapshotPusher_RegistryError(t *testing.T) {
	patPath := writePATFile(t, "token")
	fake := &fakeSnapshotPushDocker{err: errors.New("registry 401 unauthorized")}
	pusher := newTestPusher(t, patPath, fake)

	_, err := pusher.PushOnce(context.Background(), &models.SandboxSnapshot{
		Name: "snap", Image: "img:1",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	// The error must mention the registry response so operators can
	// triage from the reconciler logs without re-running.
	if !strings.Contains(err.Error(), "registry 401") {
		t.Fatalf("error %q missing registry response", err.Error())
	}
	// The PAT must never appear in the surfaced error message.
	if strings.Contains(err.Error(), "token") {
		t.Fatalf("error leaks PAT: %q", err.Error())
	}
}

func TestSnapshotPusher_MissingFields(t *testing.T) {
	patPath := writePATFile(t, "token")
	fake := &fakeSnapshotPushDocker{}
	pusher := newTestPusher(t, patPath, fake)

	cases := []struct {
		name string
		snap *models.SandboxSnapshot
	}{
		{"nil snapshot", nil},
		{"missing image", &models.SandboxSnapshot{Name: "snap"}},
		{"missing name", &models.SandboxSnapshot{Image: "img:1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pusher.PushOnce(context.Background(), tc.snap); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	if len(fake.calls) != 0 {
		t.Fatalf("expected no docker calls, got %d", len(fake.calls))
	}
}

func TestNewSnapshotPusher_DisabledReturnsNil(t *testing.T) {
	pusher, err := NewSnapshotPusher(SnapshotPushConfig{Enabled: false}, nil, nil)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if pusher != nil {
		t.Fatal("disabled config must return nil pusher")
	}
}

func TestSnapshotNeedsPush(t *testing.T) {
	cases := []struct {
		name string
		snap *models.SandboxSnapshot
		want bool
	}{
		{"nil", nil, false},
		{"local-only", &models.SandboxSnapshot{ImageDistributionMode: models.ImageDistributionLocalOnly}, true},
		{"aocr", &models.SandboxSnapshot{ImageDistributionMode: models.ImageDistributionAOCR}, false},
		{"external", &models.SandboxSnapshot{ImageDistributionMode: models.ImageDistributionExternalRegistry}, false},
		{"unset", &models.SandboxSnapshot{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SnapshotNeedsPush(tc.snap); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}
