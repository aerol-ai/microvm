package daemon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/aerol-ai/microvm/internal/config"
	cntrdriver "github.com/aerol-ai/microvm/internal/runtime/containerd"
	"github.com/aerol-ai/microvm/pkg/docker"
	"github.com/aerol-ai/microvm/pkg/models"
)

// fakeEngine is an engineImageArchiver that keeps what it was given.
type fakeEngine struct {
	imported  string
	exportOK  bool
	exportErr error
}

func (e *fakeEngine) ImportRootfsImage(_ context.Context, ref string, rootfs io.Reader) (string, error) {
	b, _ := io.ReadAll(rootfs)
	e.imported = ref + "=" + string(b)
	return "sha256:" + ref, nil
}

func (e *fakeEngine) ExportImageArchive(_ context.Context, ref string, w io.Writer) (bool, error) {
	if e.exportErr != nil {
		_, _ = io.WriteString(w, "partial")
		return false, e.exportErr
	}
	if !e.exportOK {
		return false, nil
	}
	_, err := io.WriteString(w, "archive-of-"+ref)
	return true, err
}

func TestFirecrackerImageStoreOpensAnArchiveOnDisk(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "templates", "_exports")
	engine := &fakeEngine{exportOK: true}
	s := &firecrackerImageStore{engine: engine, transport: "docker-archive", dir: dir}

	id, err := s.ImportRootfs(context.Background(), "aerolvm-snapshot/abc:latest", strings.NewReader("files"))
	if err != nil || id != "sha256:aerolvm-snapshot/abc:latest" || engine.imported != "aerolvm-snapshot/abc:latest=files" {
		t.Fatalf("import: id %q err %v engine %q", id, err, engine.imported)
	}

	src, release, ok, err := s.OpenImage(context.Background(), "aerolvm-snapshot/abc:latest")
	if err != nil || !ok || !strings.HasPrefix(src, "docker-archive:"+dir+string(filepath.Separator)) {
		t.Fatalf("open: src %q ok %v err %v", src, ok, err)
	}
	path := strings.TrimPrefix(src, "docker-archive:")
	if b, _ := os.ReadFile(path); string(b) != "archive-of-aerolvm-snapshot/abc:latest" {
		t.Fatalf("archive content = %q", b)
	}
	release()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("archive still there after release: %v", err)
	}
}

func TestFirecrackerImageStoreLeavesNothingBehindWhenItCannotOpen(t *testing.T) {
	for name, engine := range map[string]*fakeEngine{
		"missing image": {},
		"export error":  {exportErr: errors.New("engine down")},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			s := &firecrackerImageStore{engine: engine, transport: "oci-archive", dir: dir}
			src, release, ok, err := s.OpenImage(context.Background(), "aerolvm-snapshot/abc:latest")
			if ok || src != "" || release != nil || (engine.exportErr != nil) != (err != nil) {
				t.Fatalf("src %q ok %v err %v", src, ok, err)
			}
			if left, _ := os.ReadDir(dir); len(left) != 0 {
				t.Fatalf("left in the dir: %v", left)
			}
		})
	}
	// A dir that cannot be created is an error, not a panic.
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &firecrackerImageStore{engine: &fakeEngine{exportOK: true}, transport: "oci-archive", dir: filepath.Join(file, "sub")}
	if _, _, _, err := s.OpenImage(context.Background(), "x"); err == nil {
		t.Fatal("an uncreatable dir gave no error")
	}
}

// The engine is picked the way the snapshot pusher picks its backend, so
// the image lands where the pusher reads it.
func TestNewFirecrackerImageStorePicksTheNodesEngine(t *testing.T) {
	dockerClient := &docker.Client{}
	cfg := config.Config{FirecrackerTemplatesDir: "/var/lib/sandboxd/firecracker/templates", ContainerEngine: models.ContainerEngineDocker}
	s, ok := newFirecrackerImageStore(cfg, dockerClient, nil).(*firecrackerImageStore)
	if !ok || s.engine != dockerClient || s.transport != "docker-archive" || s.dir != "/var/lib/sandboxd/firecracker/templates/_exports" {
		t.Fatalf("docker node: %+v", s)
	}

	ctd := &containerdEngineWiring{driver: cntrdriver.New(cntrdriver.Config{}, nil, slog.Default())}
	cfg.ContainerEngine = models.ContainerEngineContainerd
	s, ok = newFirecrackerImageStore(cfg, dockerClient, ctd).(*firecrackerImageStore)
	if !ok || s.engine != ctd.driver || s.transport != "oci-archive" {
		t.Fatalf("containerd node: %+v", s)
	}

	if store := newFirecrackerImageStore(config.Config{}, nil, nil); store != nil {
		t.Fatalf("no engine: %+v, want nil", store)
	}
}

func TestFirecrackerImageStoreFailsWhenItCannotCreateTheArchive(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root writes into a read-only dir")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	s := &firecrackerImageStore{engine: &fakeEngine{exportOK: true}, transport: "oci-archive", dir: dir}
	if _, _, ok, err := s.OpenImage(context.Background(), "x"); ok || err == nil {
		t.Fatalf("ok %v err %v, want an error", ok, err)
	}
}
